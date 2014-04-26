
class Hash
	def store_if( truth, key, val )
		if truth
			self[key] = val
		end
		self
	end
end

module OAP
  module Processors

	def escape( in_str )
		URI::escape( in_str )
	end

	def sanitize_to_RFC_3986( in_str, double_enc = true ) # if you want it done right...
		raise Exception "FAIL! #{in_str.class} is not a String!" unless in_str.is_a?( String )
		{
			"\n"  =>	"%0D%0A", # or "%0D" or "%0A"
			" "   =>	"%20",
			"\""  =>	"%22",
#			"-"   =>	"%2D", # http://oauth.net/core/1.0/#rfc.section.5.1
#			"."   =>	"%2E", # http://oauth.net/core/1.0/#rfc.section.5.1
			"<"   =>	"%3C",
			">"   =>	"%3E",
			"\\"  =>	"%5C", 
			"^"   =>	"%5E",
#			"_"   =>	"%5F", # http://oauth.net/core/1.0/#rfc.section.5.1
			"`"   =>	"%60",
			"{"   =>	"%7B",
			"|"   =>	"%7C",
			"}"   =>	"%7D",
#			"~"   =>	"%7E", # http://oauth.net/core/1.0/#rfc.section.5.1
			"!"   =>	"%21",
			"#"   =>	"%23",
			"$"   =>	"%24",
			"&"   =>	"%26",
			"'"   =>	"%27",
			"("   =>	"%28",
			")"   =>	"%29",
			"*"   =>	"%2A",
			"+"   =>	"%2B",
			","   =>	"%2C",
			"/"   =>	"%2F", # Pay attention to root urls!
			":"   =>	"%3A", # Pay attention to root urls!
			";"   =>	"%3B",
			"="   =>	"%3D",
			"?"   =>    "%3F",
			"@"   =>	"%40",
			"["   =>	"%5B",
			"]"   =>	"%5D"
		}.store_if( double_enc, "%", "%25" ).each do | k, v |
			in_str = in_str.split( k ).join( v )
		end
		return in_str
	end

	def process_two_leg
		[ 'oauth_callback', 'oauth_token', 'oauth_verifier', 'scope' ].each do | val |
			@params.delete val if !!@params[ val ]
		end
		raise Exception "FAIL! @params is missing some keys!" unless [
			'oauth_consumer_key',
			'oauth_nonce',
			'oauth_signature',
			'oauth_signature_method',
			'oauth_timestamp',
			'oath_version' ].all? { | val | @params.key? val; }
	end

	def process_three_leg_request_token
		[ 'oauth_token', 'oauth_verifier' ].each do | val |
			@params.delete val if !!@params[ val ]
		end
		raise Exception "FAIL! @params is missing some keys!" unless [
			'oauth_consumer_key',
			'oauth_nonce',
			'oauth_signature',
			'oauth_signature_method',
			'oauth_timestamp',
			'oauth_callback', 
			'scope',
			'oath_version' ].all? { | val | @params.key? val; }
	end

	def process_three_leg_access_token
		[ 'oauth_callback', 'scope' ].each do | val |
			@params.delete val if !!@params[ val ]
		end
		raise Exception "FAIL! @params is missing some keys!" unless [
			'oauth_consumer_key',
			'oauth_nonce',
			'oauth_signature',
			'oauth_signature_method',
			'oauth_timestamp',
			'oauth_token',
			'oauth_verifier',
			'oath_version' ].all? { | val | @params.key? val; }
	end

	def process_three_leg_endpoint
		[ 'oauth_callback', 'oauth_verifier', 'scope' ].each do | val |
			@params.delete val if !!@params[ val ]
		end
		raise Exception "FAIL! @params is missing some keys!" unless [
			'oauth_consumer_key',
			'oauth_nonce',
			'oauth_signature',
			'oauth_signature_method',
			'oauth_timestamp',
			'oauth_token',
			'oath_version' ].all? { | val | @params.key? val; }
	end

	def process_url_security
		if @use_ssl
			if !!@server_uri[ "http://" ]
				@server_uri = @server_uri.split( "http://" ).join( "https://" )
			end
			if !!@params[ 'oauth_callback' ]
				if !!@params[ 'oauth_callback' ][ "http://" ]
					@params[ 'oauth_callback' ] = @params[ 'oauth_callback' ].split( "http://" ).join( "https://" )
				end
			end
		else
			if !!@server_uri[ "https://" ]
				@server_uri = @server_uri.split( "https://" ).join( "http://" )
			end
			if !!@params[ 'oauth_callback' ]
				if !!@params[ 'oauth_callback' ][ "https://" ]
					@params[ 'oauth_callback' ] = @params[ 'oauth_callback' ].split( "https://" ).join( "http://" )
				end
			end
		end
	end

	def process_request_data( post_data = nil ) # I've split the request_data method for testing purposes.
		raise Exception "FAIL! Problem found with post_data!" unless post_data.nil? or post_data.is_a?( String )

		process_url_security

		if @client_method == 'POST'
			# post_data here should be your encoded POST string, NOT an array
			return @server_uri, post_data.to_s, { 'Authorization' => generate_header }
		else
			return @server_uri, { 'Authorization' => generate_header }
		end
	end

  end
end