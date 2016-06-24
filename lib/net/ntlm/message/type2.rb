require 'unicode_utils/upcase'

module Net
  module NTLM
    class Message
      # @private false
      class Type2 < Message
        string :sign, size: 8, value: SSP_SIGN
        int32le :type, value: 2
        security_buffer :target_name, size: 0, value: ""
        int32le :flag, value: DEFAULT_FLAGS[:TYPE2]
        int64le :challenge, value: 0
        int64le :context, value: 0, active: false
        security_buffer :target_info, value: "", active: false
        string :os_version, size: 8, value: "", active: false

        # Generates a Type 3 response based on the Type 2 Information
        # @return [Type3]
        # @option arg [String] :username The username to authenticate with
        # @option arg [String] :password The user's password
        # @option arg [String] :domain ('') The domain to authenticate to
        # @option opt [String] :workstation (Socket.gethostname) The name of the calling workstation
        # @option opt [Boolean] :use_default_target (false) Use the domain supplied by the server in the Type 2 packet
        # @note An empty :domain option authenticates to the local machine.
        # @note The :use_default_target has precedence over the :domain option
        def response(arg, opt = {})
          usr = UnicodeUtils.upcase(arg[:user])
          pwd = arg[:password]
          domain = arg[:domain] ? UnicodeUtils.upcase(arg[:domain]) : ""

          fail ArgumentError, "user and password have to be supplied" if usr.nil? || pwd.nil?

          if opt[:workstation]
            ws = opt[:workstation]
          else
            ws = Socket.gethostname
          end

          if opt[:client_challenge]
            cc = opt[:client_challenge]
          else
            cc = rand(MAX64)
          end
          cc = NTLM.pack_int64le(cc) if cc.is_a?(Integer)
          opt[:client_challenge] = cc

          if flag?(:OEM) && opt[:unicode]
            usr = NTLM::EncodeUtil.decode_utf16le(usr)
            pwd = NTLM::EncodeUtil.decode_utf16le(pwd)
            ws  = NTLM::EncodeUtil.decode_utf16le(ws)
            domain = NTLM::EncodeUtil.decode_utf16le(domain)
            opt[:unicode] = false
          end

          if flag?(:UNICODE) && !opt[:unicode]
            usr = NTLM::EncodeUtil.encode_utf16le(usr)
            pwd = NTLM::EncodeUtil.encode_utf16le(pwd)
            ws  = NTLM::EncodeUtil.encode_utf16le(ws)
            domain = NTLM::EncodeUtil.encode_utf16le(domain)
            opt[:unicode] = true
          end

          domain = target_name if opt[:use_default_target]
          ti = target_info
          chal = self[:challenge].serialize

          if opt[:ntlmv2]
            ar = { ntlmv2_hash: NTLM.ntlmv2_hash(usr, pwd, domain, opt), challenge: chal, target_info: ti }
            lm_res = NTLM.lmv2_response(ar, opt)
            ntlm_res = NTLM.ntlmv2_response(ar, opt)
          elsif flag?(:NTLM2_KEY)
            ar = { ntlm_hash: NTLM.ntlm_hash(pwd, opt), challenge: chal }
            lm_res, ntlm_res = NTLM.ntlm2_session(ar, opt)
          else
            ar = { lm_hash: NTLM.lm_hash(pwd), challenge: chal }
            lm_res = NTLM.lm_response(ar)
            ar = { ntlm_hash: NTLM.ntlm_hash(pwd, opt), challenge: chal }
            ntlm_res = NTLM.ntlm_response(ar)
          end

          Type3.create(lm_response: lm_res,
                       ntlm_response: ntlm_res,
                       domain: domain,
                       user: usr,
                       workstation: ws,
                       flag: flag)
        end
      end
    end
  end
end
