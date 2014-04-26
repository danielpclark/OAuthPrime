$: << File.join(File.dirname(__FILE__), "/../lib")
$: << File.join(File.dirname(__FILE__), "/../lib/oauthprime")
require 'minitest'
require 'minitest/unit'
require 'minitest/autorun'
require 'oauthprime'
require 'json'


# Before website can ask user to grant it access to the
# resource, it must first establish a set of temporary credentials with
# said website to identify the delegation request. To do so,
# the client sends the following HTTPS [RFC2818] request to the server


class TestOAuthPrime < Minitest::Test

	def split_headers( in_str )
		a = { }
		in_str.split( "&" ).each do |pairs|
			k , v = pairs.split( "=" )
			a[ k ] = v
		end
		return a.sort
	end

	def setup
		@i = OAuthPrime.new(
			:consumer_key		=>	'abcdefghijklmnop',
			:consumer_secret	=>	'zyxwvutsrqponm'
		)
	end

	def test_key_variable
		assert !!defined? @i.consumer_key, "No consumer_key variable defined!"
		refute @i.consumer_key.nil?, "Unable to refute consumer_key variable as nil!"
	end

	def test_secret_variable
		assert !!defined? @i.consumer_secret, "No consumer_secret variable defined!"
		refute @i.consumer_secret.nil?, "Unable to refute consumer_secret variable as nil!"
	end

	def test_method_variable
		assert !!defined? @i.client_method, "No client_method variable defined!"
		assert @i.client_method == "GET" || @i.client_method == "POST", "The method varaible not set as either GET or POST!"
	end

	def test_uri_variable
		assert !!defined? @i.server_uri, "No server_uri variable defined!"
		assert ( !!@i.server_uri[ "http" ] and !!@i.server_uri[ "://" ] ), "#{@i.server_uri} is not valid url provided for server_uri!"
	end

	def test_generate_nonce
		nonce = @i.generate_nonce( 7 )
		assert nonce.is_a?( String ), "FAIL! nonce is not a string!"
		refute !!nonce[ "\n" ], "FAIL! nonce contains a new line character!"
	end

	def test_params_variable
		assert !!defined? @i.params, "No params variable defined!"
		refute @i.params.nil?, "Unable to refute params variable as nil!"
		refute @i.params.empty?, "Unable to refute params variable as empty!"
	end

	def test_generate_header
		@i.generate_signature
		assert !!defined? @i.generate_header, "No generate_header method defined!"
		istring = @i.generate_header
		assert istring.class == String, "FAIL! Method generate_header didn't return a string!"
	end

	def test_signature_base_variable
		assert !!defined? @i.signature_base, "No signature_base variable defined!"
		refute @i.signature_base.nil?, "Unable to refute signature_base variable as nil!"
		refute @i.signature_base.empty?, "Unable to refute signature_base variable as empty!"
		refute !!@i.signature_base[ "oauth_signature%3D" ], "The oauth_signature MUST be excluded from signature_base!"
		#puts @i.signature_base
	end

	def test_sign_makes_signature
		@i.generate_signature
		assert @i.params.has_key?( "oauth_signature" ), "Failed to verify oauth_signature in params!"
		assert @i.params[ "oauth_signature" ].class == String, "FAIL! oauth_signature in params isn't a String!"
		refute @i.params[ "oauth_signature" ].empty?, "FAIL! oauth_signature in params is empty!"
	end

	def test_sign_by_twitter_example # https://dev.twitter.com/docs/auth/creating-signature
		# sign( consumer_secret, access_token, signature_base )		
		@i = OAuthPrime.new(
			:client_method		=> "POST",
			:consumer_key		=> "xvz1evFS4wEEPTGEFPHBog",
			:consumer_secret	=> "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
			:server_uri			=> "https://api.twitter.com/1/statuses/update.json",
			:access_token_secret=> "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"
		)
		
		@i.params[ 'oauth_signature_method'	]	=	"HMAC-SHA1"
		@i.params[ 'oauth_timestamp'		]	=	"1318622958"
		@i.params[ 'oauth_nonce'			]	=	"kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"
		@i.params[ 'oauth_version'			]	=	"1.0"
		@i.params[ 'oauth_token'			]	=	"370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"

		given = @i.generate_signature( @i.consumer_secret, @i.access_token, @i.generate_signature_base_string )
		expected = "tnnArxj06cWHq44gCs1OSKk/jLY="
		assert_equal expected, given, "FAIL! sign_by_example expected result did not match given!"
	end

	def test_sign_by_RFC_example_1_2 # source http://tools.ietf.org/pdf/rfc5849.pdf
		# sign( consumer_secret, access_token, signature_base )
		@i = OAuthPrime.new(
			:client_method		=> "POST",
			:consumer_key		=> "dpf43f3p2l4k3l03",
			:consumer_secret	=> "kd94hf93k423kf44",
			:server_uri			=> "https://photos.example.net/initiate"
		)
		@i.params[ 'oauth_signature_method'	]	=	"HMAC-SHA1"
		@i.params[ 'oauth_timestamp'		]	=	"137131200"
		@i.params[ 'oauth_nonce'			]	=	"wIjqoS"
		@i.params[ 'oauth_callback'			]	=	"http://printer.example.com/ready"
		@i.params[ 'oauth_version'			]	=	"1.0"
		@i.params[ 'realm'					]	=	"Photos"

		given = @i.generate_signature( @i.consumer_secret, @i.access_token, @i.generate_signature_base_string )
		expected = "74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D"
		assert_equal expected, given, "FAIL! sign_by_example expected result did not match given!"
	end

	def test_RFC_example_3_5_1 # source http://tools.ietf.org/pdf/rfc5849.pdf
		@i = OAuthPrime.new(
			:client_method		=> "POST",
			:consumer_key 		=> "0685bd9184jfhq22",
			:access_token 		=> "ad180jjd733klru7",
		)
		@i.params[ 'oauth_signature_method'	]	=	"HMAC-SHA1"
		@i.params[ 'oauth_signature'		]	=	"wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D"
		@i.params[ 'oauth_timestamp'		]	=	"137131200"
		@i.params[ 'oauth_nonce'			]	=	"4572616e48616d6d65724c61686176"
		@i.params[ 'oauth_version'			]	=	"1.0"

		example_str = "oauth_consumer_key=0685bd9184jfhq22&oauth_token=ad180jjd733klru7&oauth_signature_method=HMAC-SHA1&oauth_signature=wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D&oauth_timestamp=137131200&oauth_nonce=4572616e48616d6d65724c61686176&oauth_version=1.0"
		test_out = @i.process_request_data[ -1 ][ "Authorization" ]

		assert_equal split_headers(	example_str ), split_headers( test_out ), "FAIL! Data is not equal for RFC example 3.5.1!"
	end

	def test_Generating_generate_signature_base_string_oauth_net_core_1_0_Appendix_A_5_1 # http://oauth.net/core/1.0/#rfc.section.A.5.1
		# sign( consumer_secret, access_token, signature_base )
		@i = OAuthPrime.new(
			:client_method		=> "POST",
			:consumer_key		=> "dpf43f3p2l4k3l03",
			:consumer_secret	=> "kd94hf93k423kf44",
			:server_uri			=> "https://photos.example.net/initiate"
		)
		@i.params[ 'oauth_signature_method'	]	=	"HMAC-SHA1"
		@i.params[ 'oauth_timestamp'		]	=	"137131200"
		@i.params[ 'oauth_nonce'			]	=	"wIjqoS"
		@i.params[ 'oauth_callback'			]	=	"http://printer.example.com/ready"
		@i.params[ 'oauth_version'			]	=	"1.0"
		@i.params[ 'realm'					]	=	"Photos"

		given = @i.generate_signature( @i.consumer_secret, @i.access_token, @i.generate_signature_base_string )
		expected = "74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D"
		assert_equal expected, given, "FAIL! sign_by_example expected result did not match given!"
	end

# allthekingshorses # http://oauth-sandbox.sevengoslings.net/ # thekingsmen
#-------------------------------------------------------------
# Hi allthekingshorses. Welcome to the OAuth Sandbox. (Logout)
# You are now ready to test your Consumer against this Service Provider. You will probably need these informations: 
# Request Token URL: http://oauth-sandbox.sevengoslings.net/request_token 
# User Authorization URL: http://oauth-sandbox.sevengoslings.net/authorize 
# Access Token URL: http://oauth-sandbox.sevengoslings.net/access_token 
#
# This Service Provider has two protected resources. One that only requires a two-legged call and one that requires a full three-legged call. 
# The URLs for these resources are: 
# Two-Legged: http://oauth-sandbox.sevengoslings.net/two_legged 
# Three-Legged: http://oauth-sandbox.sevengoslings.net/three_legged 
#-------------------------------------------------------------

	def test_request_data_with_sandbox # http://oauth-sandbox.sevengoslings.net
		skip( "Unskip me if everything else works." )
		@i = OAuthPrime.new( # thekingsmen
			:consumer_key		=>	'1025c758e3f21e7a',
			:consumer_secret	=>	'344eddecba2686e044bc73a46929',
			:server_uri			=>	'http://oauth-sandbox.sevengoslings.net/request_token',
			:use_ssl			=>	false,
			:client_method		=>	"POST"
		)
		@i.generate_signature
		results = @i.request_data
		puts results
	end

	def test_request_data_with_twitter
		skip( "Unskip me if everything else works." )
		# App-only authentication	https://api.twitter.com/oauth2/token
		# Request token URL			https://api.twitter.com/oauth/request_token
		# Authorize URL 			https://api.twitter.com/oauth/authorize
		# Access token URL 			https://api.twitter.com/oauth/access_token
		
		twitter_credentials = JSON::parse( File.read( File.expand_path( "../../twitter-credentials.json" ) ) )

		@i = OAuthPrime.new(
			:consumer_key		=>	twitter_credentials[ "Twitter" ][ ":consumer_key" ],
			:consumer_secret	=>	twitter_credentials[ "Twitter" ][ ":consumer_secret" ],
			:server_uri			=>	'https://api.twitter.com/oauth/request_token',
			:use_ssl			=>	true,
			:client_method		=>	"POST"
		)
		@i.params['oauth_callback'] = @i.sanitize_to_RFC_3986("http://www.twitter.com/6ftdan")
		@i.generate_signature
		#results = @i.prep_request_data
		#puts results
		results = @i.request_data
		puts results
	end
end