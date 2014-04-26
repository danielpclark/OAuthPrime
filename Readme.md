**OAuthPrime**
---
Pre-Alpha a.k.a. work in progress "right now".

Goals:
 * Code Beauty.
 * Code Simplicity.
 * Seamless Oauth 1.0+

This is your prime source for OAuth 1.0.  And may in the future
include later versions.

As of this version 0.0.2. **I would like help debugging the signing
method.**  The code is written in a way that's easy to follow.  If
you have experience with Oauth you may be able to solve why the
tests for signing the header aren't passing.  See notes.to.self.

This project is designed using TDD following stated examples as in
this document http://tools.ietf.org/pdf/rfc5849.pdf and other source.
Following a walk through OAuth 1.0 written by David Coen at
http://www.drcoen.com/2011/12/oauth-1-0-in-ruby-without-a-gem/ .  And
gratefully using http://oauth-sandbox.sevengoslings.net/ to test
the OAuthPrime code out (thanks to Morten Fangel). ^_^
Everything you need for TDD!  For other useful links see notes.to.self.

**Why OAuth?**

In order for the client to access resources, it first has to obtain
permission from the resource owner. This permission is expressed in
the form of a token and matching shared-secret. The purpose of the
token is to make it unnecessary for the resource owner to share its
credentials with the client. Unlike the resource owner credentials,
tokens can be issued with a restricted scope and limited lifetime,
and revoked independently.

**Why version OAuth 1.0 when it's depreciated?**

 * oDesk.com
