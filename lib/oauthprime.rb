$: << File.join( File.dirname( __FILE__ ), "/oauthprime" )
r = [ 'oauthprime/base', 'oauthprime/version', 'base64', 'openssl',
	'mightystring', 'uri', 'net/http' ]
r.each do | in_gem | require in_gem; end


class OAuthPrime
	attr_accessor :consumer_key, :consumer_secret, :client_method,
		:server_uri, :params, :access_token, :access_token_secret,
		:signature_base, :signing_key, :use_ssl
	
	include OAP::Processors
	include OAP::Generators

	def initialize( opts = { } )
		options = {
				:consumer_key		=>	nil,
				:consumer_secret	=> 	nil,
				:client_method		=>	"POST",
				:server_uri			=>	"https://api.site.com/resource/section.format",
				:access_token		=>	nil,
				:access_token_secret=>	nil,
				:use_ssl			=>	true
			}.merge( opts )
		@consumer_key = options[ :consumer_key ]
		@consumer_secret = options[ :consumer_secret ]
		@client_method = options[ :client_method ]
		@server_uri = options[ :server_uri ]
		@params = generate_params
		@access_token = options[ :access_token ]
		@access_token_secret = options[ :access_token_secret ]
		@signature_base = generate_signature_base_string
		@use_ssl = options[ :use_ssl ]
	end

	def request_data( post_data = nil )
		raise Exception "FAIL! Problem found with post_data!" unless post_data.nil? or post_data.is_a?( String )

		http = Net::HTTP.new( URI.parse( @server_uri ).host, @use_ssl ? 443 : 80 )

		http.use_ssl = @use_ssl; if @use_ssl
			http.verify_mode = OpenSSL::SSL::VERIFY_PEER
			http.verify_depth = 9
		end
		
		prd = process_request_data( post_data )
		
		if @client_method == 'POST'
			resp, data = http.post( prd[ 0 ], prd[ 1 ], prd[ 2 ] )
		else
			resp, data = http.get( prd[ 0 ], prd[ 1 ] )
		end
		
		return resp.code, resp.body, data
	end

end
