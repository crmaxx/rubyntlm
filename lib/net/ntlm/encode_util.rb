module Net
module NTLM
  class EncodeUtil
    # Use native 1.9 string encoding functions

    # Decode a UTF16 string to a ASCII string
    # @param [String] str The string to convert
    def self.decode_utf16le(str)
      str.force_encoding(Encoding::UTF_16LE)
      str.encode(Encoding::UTF_8, Encoding::UTF_16LE).force_encoding('UTF-8')
    end

    # Encodes a ASCII string to a UTF16 string
    # @param [String] str The string to convert
    # @note This implementation may seem stupid but the problem is that UTF16-LE and UTF-8 are incompatiable
    #   encodings. This library uses string contatination to build the packet bytes. The end result is that
    #   you can either marshal the encodings elsewhere of simply know that each time you call encode_utf16le
    #   the function will convert the string bytes to UTF-16LE and note the encoding as UTF-8 so that byte
    #   concatination works seamlessly.
    def self.encode_utf16le(str)
      str = str.force_encoding('UTF-8') if [::Encoding::ASCII_8BIT, ::Encoding::US_ASCII].include?(str.encoding)
      str.dup.force_encoding('UTF-8').encode(Encoding::UTF_16LE, Encoding::UTF_8).force_encoding('UTF-8')
    end
  end
end
end
