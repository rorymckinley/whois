require 'whois/record/parser/base'
require 'whois/record/scanners/whois.registry.net.za'


module Whois
  class Record
    class Parser
      #--
      # @note This parser is just a stub and provides only a few basic methods
      #   to check for domain availability and get domain status.
      #   Please consider to contribute implementing missing methods.
      # ++
      class WhoisRegistryNetZa < Base
        include Scanners::Nodable

        property_supported :available? do
          node(:available)
        end

        property_supported :registered? do
          !available?
        end

        property_supported :nameservers do
          if registered?
            node(:nameservers).map { |nameserver| Record::Nameserver.new(:name => nameserver) }
          else
            []
          end
        end

        property_supported :registrar do
          if node(:registrar_id)
            Whois::Record::Registrar.new(:name => node(:registrar_name), :id => node(:registrar_id))
          else
            nil
          end
        end

        property_supported :registrant_contacts do
          if registered?
            build_registrant_contacts
          else
            []
          end
        end

        def parse
          Scanners::WhoisRegistryNetZa.new(content_for_scanner).parse
        end

        private

        def build_registrant_contacts
          contact = Whois::Record::Contact.new(
            {:type => Whois::Record::Contact::TYPE_REGISTRANT}.merge(registrant_details).merge(registrant_address_details)
          )
        end

        def registrant_details
          if node(:registrant_name)
            { :name => node(:registrant_name), :email => node(:registrant_email), :phone => node(:registrant_telephone), :fax => node(:registrant_fax)}
          end
        end

        def registrant_address_details
          { :address => node(:registrant_address) }
        end
      end
    end
  end
end
