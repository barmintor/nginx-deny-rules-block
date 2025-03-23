require './deny_rules_block'

describe DenyRulesBlock do
	def pb(i)
		i.to_s(2).rjust(8, '0')
	end
	subject(:parser) { described_class.new}
	let(:full_byte) { '11111111' }
	describe 'pb' do
		it 'works' do
			expect(pb(255)).to eql '11111111'
			expect(pb(127)).to eql '01111111'
			expect(pb(4)).to eql '00000100'
		end
	end
	describe 'cidr_to_binary_rep' do
		it 'parses a plain IP' do
			expect(parser.cidr_to_binary_rep("255.255.255.255")).to eql "#{pb(255)}#{pb(255)}#{pb(255)}#{pb(255)}"
		end
		it 'parses a subnet mask' do
			expect(parser.cidr_to_binary_rep("255.255.255.255/23")).to eql "11111111111111111111111"
			expect(parser.cidr_to_binary_rep("192.158.51.0/24")).to eql "110000001001111000110011"
			expect(parser.cidr_to_binary_rep("199.223.0.0/20")).to eql  "#{pb(199)}#{pb(223)}0000"
		end
	end
	describe 'binary_rep_to_cidr' do
		it 'serializes a plain IP' do
			expect(parser.binary_rep_to_cidr([full_byte,full_byte,full_byte,full_byte])).to eql "255.255.255.255"
		end		
		it 'serializes a subnet mask' do
			expect(parser.binary_rep_to_cidr([full_byte,full_byte,'1111111'])).to eql "255.255.254.0/23"
		end
	end
	describe 'blocked_exactly?' do
		let(:exact_match) { "66.249.66.160/27" }
		let(:not_matching) { "128.249.66.160/27" }
		before do
			parser.index(["deny #{exact_match};"])
		end
		it 'returns the rule when matching' do
			expect(parser.blocked_exactly?(exact_match)).to eql(exact_match)
		end
		it 'returns nil when not matching' do
			expect(parser.blocked_exactly?(not_matching)).to be_nil
		end
	end
	describe 'blocked_in_superset?' do
		let(:exact_match) { "66.249.66.160/16" }
		let(:plain_ip_match) { "66.249.66.160" }
		let(:plain_ip_mismatch) { "66.250.66.160" }
		let(:subset_match_whole) { "66.249.66.128/24" }
		let(:subset_match_fraction) { "66.249.66.160/19" }
		let(:not_matching) { "66.250.66.160/19" }
		before do
			parser.index(["deny #{exact_match};"])
		end
		it 'returns the rule when matching' do
			expect(parser.blocked_in_superset?(exact_match)).to eql(exact_match)
			expect(parser.blocked_in_superset?(plain_ip_match)).to eql(exact_match)
		end
		it 'returns the rule when matching whole-byte superset' do
			expect(parser.blocked_in_superset?(subset_match_whole)).to eql(exact_match)
		end
		it 'returns the rule when matching fractional superset' do
			expect(parser.blocked_in_superset?(subset_match_fraction)).to eql(exact_match)
		end
		it 'returns nil when not matching' do
			expect(parser.blocked_in_superset?(not_matching)).to be_nil
			expect(parser.blocked_in_superset?(plain_ip_mismatch)).to be_nil
		end
	end
	describe 'partially_blocked?' do
		let(:exact_match) { "208.81.136.0/21" }
		let(:superset_match_fraction) { "208.81.136.0/20" }
		let(:superset_match_whole) { "208.81.138.5/16" }
		let(:not_matching) { "208.81.188.0/22" }
		before do
			parser.index(["deny #{exact_match};"])
		end
		it 'returns the rule when matching whole-byte subset' do
			expect(parser.partially_blocked?(superset_match_whole)).to eql(exact_match)
		end
		it 'returns the rule when matching fractional subset' do
			expect(parser.partially_blocked?(superset_match_fraction)).to eql(exact_match)
		end
		it 'returns nil when not matching' do
			expect(parser.partially_blocked?(not_matching)).to be_nil
		end
	end
	describe 'obscure-in-decimal rules' do
		let(:exact_match) { "192.168.200.5/30" }
		let(:not_matching) { "192.168.200.9/30" }
		let(:matching) { "192.168.200.6/30" }
		before do
			parser.index(["deny #{exact_match};"])
		end
		it 'works' do
			expect(parser.blocked_exactly?(matching)).to eql(exact_match)
			expect(parser.blocked_exactly?(not_matching)).to be_nil
			expect(parser.blocked_in_superset?(not_matching)).to be_nil
			expect(parser.partially_blocked?(not_matching)).to be_nil
		end
	end
end