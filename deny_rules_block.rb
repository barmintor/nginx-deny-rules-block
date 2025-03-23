#!/usr/bin/env ruby
require 'json'

class DenyRulesBlock
	# deny pattern for nginx config
	DENY = /deny\s+([\d\.]+(\/\d+));/
	DUCKDUCKIP = /-\s+((\d{1,3})(\.\d{1,3}){3})/

	def initialize(block_index = {})
		@block_index = block_index
	end

	def reset!(block_index = {})
		@block_index = block_index
	end

	def cidr_to_binary_rep(cidr)
		base, num_bits = cidr.split('/')
		num_bits = 32 unless num_bits.to_s != ''
		base.split('.').map(&:to_i).map { |i| i.to_s(2).rjust(8, '0') }.join.slice(0, num_bits.to_i)
	end

	def binary_rep_to_cidr(chunks)
		bits = 0
		chunks.each { |chunk| bits += chunk.length unless chunk == '*' }
		(0..3).each { |ix| chunks[ix] ||= '0' }
		ip = chunks.map { |chunk| chunk == '*' ? 0 : chunk.ljust(8, '0').to_i(2) }.join('.')
		bits == 32 ? ip : "#{ip}/#{bits}"
	end

	def index(deny_rule_iterable)
		deny_rule_iterable.each do |line|
			line.strip!
			m = line.match(DENY)
			if m
				prefix = cidr_to_binary_rep(m[1])
				chunks = [prefix.slice(0,8), prefix.slice(8,8), prefix.slice(16,8), prefix.slice(24,8)]
				chunks.map! {|c| c.to_s == '' ? '*' : c }
				l1 = (@block_index[chunks[0]] ||= {})
				l2 = (l1[chunks[1]] ||= {})
				l3 = (l2[chunks[2]] ||= {})
				l3[chunks[3]] = m[1]
			end
		end
	end

	def key_for(cidr, chunks = nil)
		if chunks.nil?
			prefix = cidr_to_binary_rep(cidr)
			key = [prefix.slice(0,8), prefix.slice(8,8), prefix.slice(16,8), prefix.slice(24,8)].map {|c| c.to_s == '' ? '*' : c }
		else
			key = chunks + []
			(0..3).each {|ix| key[ix] ||= '*'}
		end
		key
	end

	def blocked_exactly?(cidr, chunks = nil)
		key = key_for(cidr, chunks)
		@block_index.dig(*key)
	end

	def blocked_in_superset?(cidr, chunks = nil)
		key = key_for(cidr, chunks)
		[3,2,1].each do |ix|
			wc = key[0...ix] + (0..(3 - ix)).inject([]) { |a| a << '*' }
			partial_block = @block_index.dig(*wc)
			return partial_block if partial_block
		end
		return nil
	end

	def partially_blocked?(cidr, chunks = nil)
		key = key_for(cidr, chunks)
		[3,2,1,0].each do |ix|
			partial_block = @block_index.dig(*key[0..(ix-1)])
			next unless partial_block
			if key[ix] == '*'
				binary_rep_chunks = key[0..(ix-1)] << partial_block.keys.first
				(3 - ix).times { binary_rep_chunks << '*' }
				return binary_rep_to_cidr(binary_rep_chunks)
			end
			partial_match_key = partial_block.keys.detect { |k| k.start_with?(key[ix]) }
			next unless partial_match_key
			if partial_match_key != key[ix]
				binary_rep_chunks = key[0..(ix-1)] << partial_match_key
				(3 - ix).times { binary_rep_chunks << '*' }
				return binary_rep_to_cidr(binary_rep_chunks)
			elsif partial_block.dig(partial_match_key, '*')
			elsif partial_block[partial_match_key].is_a? String
			end
		end
		return nil
	end
end

if __FILE__ == $0
	if !ARGV[0] or !File.exists?(ARGV[0])
		puts "ruby deny_rules.rb #{ARGV.join} not valid"
		puts "usage: ruby deny_rules.rb $DENY_RULES_PATH ...$CIDRs"
		puts "$DENY_RULES_PATH should be the path to a list of deny rules"
		puts "deny rules should be of the format 'deny $CIDR;'"
		puts "see also https://nginx.org/en/docs/http/ngx_http_access_module.html#deny"
		puts "Special values for $CIDRs:"
		puts "\tbing: check published BingBot subnets"
		puts "\tddg: check published DuckDuckBot IPs"
		puts "\tgoogle: check published GoogleBot subnets"
		puts "\t-: read CIDRs from STDIN"
		puts "example: ruby deny_rules.rb /etc/nginx/blockips.inc 66.249.66.96/27"
		puts "example: echo '66.249.66.96/27' | ruby deny_rules.rb /etc/nginx/blockips.inc -"
		return
	end
	require 'json'
	require 'open-uri'

	nginx_deny_rules = DenyRulesBlock.new

	open(ARGV[0], 'rb') do |io|
		nginx_deny_rules.index(io)
	end

	def check_cidr(deny_rules, cidr, label = 'argument')
		prefix = deny_rules.cidr_to_binary_rep(cidr)
		chunks = [prefix.slice(0,8), prefix.slice(8,8), prefix.slice(16,8), prefix.slice(24,8)].map {|c| c.to_s == '' ? '*' : c }
		blocked = deny_rules.blocked_exactly?(cidr, chunks)
		if blocked
			puts "#{label} CIDR #{cidr} blocked by deny rule for #{blocked}"
			return
		end

		blocked = deny_rules.blocked_in_superset?(cidr, chunks)
		if blocked
			puts "#{label} CIDR #{cidr} blocked by superset deny rules for #{blocked}"
			return
		end

		blocked = deny_rules.partially_blocked?(cidr, chunks)
		if blocked
			puts "#{label} CIDR #{cidr} partially blocked by deny rules such as #{blocked}"
			return
		end
	end

	def check_google_bots(deny_rules)
		# see also https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot
		bot_lists = %W(googlebot.json special-crawlers.json user-triggered-fetchers.json user-triggered-fetchers-google.json)
		bot_lists.each do |bot_list|
			unless File.exists?(bot_list)
				URI.open("https://developers.google.com/static/search/apis/ipranges/#{bot_list}") do |io|
					IO.copy_stream(io, "./#{bot_list}")
				end
			end
		end
		unless File.exists?('goog.json')
			URI.open("https://www.gstatic.com/ipranges/goog.json") do |io|
				IO.copy_stream(io, "./goog.json")
			end
		end

		bot_lists.concat(['goog.json']).each do |bot_list|
			cidrs = JSON.load(File.read(bot_list))['prefixes'].select {|x| x['ipv4Prefix'] }.map {|x| x['ipv4Prefix'] }

			cidrs.each do |cidr|
				check_cidr(deny_rules, cidr, bot_list)
			end
		end
	end

	def check_bing_bots(deny_rules)
		# see also https://www.bing.com/toolbox/bingbot.json
		unless File.exists?('bingbot.json')
			URI.open("https://www.bing.com/toolbox/bingbot.json") do |io|
				IO.copy_stream(io, "./bingbot.json")
			end
		end

		['bingbot.json'].each do |bot_list|
			cidrs = JSON.load(File.read(bot_list))['prefixes'].select {|x| x['ipv4Prefix'] }.map {|x| x['ipv4Prefix'] }

			cidrs.each do |cidr|
				check_cidr(deny_rules, cidr, bot_list)
			end
		end
	end

	def check_ddg_bots(deny_rules)
		# see also https://duckduckgo.com/duckduckgo-help-pages/results/duckduckbot/
		unless File.exists?('ddg.json')
			open("./ddg.json", 'wb') do |out|
				json = { creationTime: DateTime.now.to_s, prefixes: [] }
				# No JSON list; see https://github.com/duckduckgo/duckduckgo-help-pages/issues/124
				#URI.open("https://raw.githubusercontent.com/duckduckgo/duckduckgo-help-pages/refs/heads/master/_docs/results/duckduckbot.md") do |io|
				open("tmp/duckduckbot.md", 'rb') do |io|
					io.each do |line|
						line.strip!
						m = line.match(DenyRulesBlock::DUCKDUCKIP)
						json[:prefixes] << { ipv4Prefix: m[1] } if m
					end
				end
				out.write(JSON.pretty_generate(json))
			end
		end

		['ddg.json'].each do |bot_list|
			cidrs = JSON.load(File.read(bot_list))['prefixes'].select {|x| x['ipv4Prefix'] }.map {|x| x['ipv4Prefix'] }

			cidrs.each do |cidr|
				check_cidr(deny_rules, cidr, bot_list)
			end
		end
	end

	if ARGV[1..-1].empty?
		check_google_bots(nginx_deny_rules)
		return
	end

	keywords = {}
	bing_checked = false
	ARGV[1..-1].each do |arg|
		if arg == 'google'
			if !keywords.fetch('google', false)
				check_google_bots(nginx_deny_rules)
				keywords['google'] = true
			end
		elsif arg == 'bing'
			if !keywords.fetch('bing', false)
				check_bing_bots(nginx_deny_rules)
				keywords['bing'] = true
			end
		elsif arg == 'ddg'
			if !keywords.fetch('ddg', false)
				check_ddg_bots(nginx_deny_rules)
				keywords['ddg'] = true
			end
		elsif arg == '-'
			STDIN.readlines.each do |line|
				check_cidr(nginx_deny_rules, line.strip, 'stdin')
			end				
		else
			check_cidr(nginx_deny_rules, arg, 'argument')
		end
	end
end