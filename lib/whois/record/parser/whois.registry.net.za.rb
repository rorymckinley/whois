require 'whois/record/parser/base'


module Whois
  class Record
    class Parser
      class WhoisRegistryNetZa < Base
        property_supported :available? do
          false
        end
      end
    end
  end
end
