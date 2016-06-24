module Net
  module NTLM
    class SecurityBuffer < FieldSet
      int16le :length, value: 0
      int16le :allocated, value: 0
      int32le :offset, value: 0

      attr_accessor :active
      attr_reader :value

      def initialize(opts = {})
        super()
        @value  = opts[:value]
        @active = opts[:active].nil? ? true : opts[:active]
        @size = 8
      end

      def parse(str, offset = 0)
        if @active && str.size >= offset + @size
          super(str, offset)
          @value = str[self.offset, self.length]
          @size
        else
          0
        end
      end

      def serialize
        super if @active
      end

      def value=(val)
        @value = val
        self.length = self.allocated = val.size
      end

      def data_size
        @active ? @value.size : 0
      end
    end
  end
end
