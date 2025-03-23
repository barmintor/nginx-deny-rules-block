# DenyRules
usage: ruby deny_rules_block.rb $DENY_RULES_PATH ...$CIDRs
$DENY_RULES_PATH should be the path to a list of deny rules
deny rules should be of the format 'deny $CIDR;'
see also https://nginx.org/en/docs/http/ngx_http_access_module.html#deny
Special values for $CIDRs:
	bing: check published BingBot subnets
	ddg: check published DuckDuckBot IPs
	google: check published GoogleBot subnets
	-: read CIDRs from STDIN
example: ruby deny_rules_block.rb /etc/nginx/blockips.inc 66.249.66.96/27
example: echo '66.249.66.96/27' | ruby deny_rules_block.rb /etc/nginx/blockips.inc -