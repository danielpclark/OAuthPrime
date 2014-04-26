
module OAP
  module Generators

	attr_reader :generate_header

	def generate_nonce( size = 7 ) # Unique result needed.  No other specifics.
		return sanitize_to_RFC_3986( Base64.encode64( OpenSSL::Random.random_bytes( size ) ) )
	end

	# These 5 parameters are common to all calls
	def generate_params
		return {
			'oauth_consumer_key'		=>	@consumer_key,
			'oauth_nonce'				=>	generate_nonce,
			'oauth_signature_method'	=>	'HMAC-SHA1',
			'oauth_timestamp'			=>	Time.now.getutc.to_i.to_s,
			'oauth_version'				=>	'1.0'
		}
	end

	def generate_header( prms = @params )
		header = "" # "OAuth "
		prms.sort.each do | k, v |
			header += "#{ k }=#{ v }&"
		end
		header[0..-2]
	end

	def generate_signature_base_string
		if defined? @access_token and @access_token.is_a?(String)
			params[ 'oauth_token' ] = @access_token
		end

		gsbs = (
			@client_method.upcase +
			'&' +
			sanitize_to_RFC_3986( @server_uri ) +
			'&' +
			sanitize_to_RFC_3986(
				generate_header( 
					@params.tap { | prms |
						# "oauth_signature" parameter MUST be excluded from the signature http://tools.ietf.org/html/rfc5849#section-3.4.1.3.1
						prms.has_key?( "oauth_signature" ) ? prms.delete( "oauth_signature" ) : prms
					}
				)
			)
		)
	end

	def generate_signature( cs = @consumer_secret, acto = @access_token_secret, sb = @signature_base )
		raise Exception "FAIL! @consumer_secret is not a String in sign!" unless cs.is_a?( String )
		raise Exception "FAIL! @access_token_secret is not a String, or nil, in sign!" unless acto.is_a?( String ) or acto.nil?
		raise Exception "FAIL! @signature_base is not a String in sign!" unless sb.is_a?( String )
		raise Exception "FAIL! @signature_base's '&' count does not eqaul 2!" unless sb.index_all("&").count == 2 # index_all inherited from mightystring

		digest = OpenSSL::Digest::Digest.new( 'sha1' )
		hmac = OpenSSL::HMAC.digest( 
			digest,
			( 
				cs +
				'&' +
				acto.to_s
			),
			sb
		)
		@params[ 'oauth_signature' ] = Base64.encode64( hmac ).chomp
	end

  end
end