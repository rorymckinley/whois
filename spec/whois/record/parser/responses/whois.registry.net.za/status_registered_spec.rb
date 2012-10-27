# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.registry.net.za/status_registered.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/record/parser/whois.registry.net.za.rb'

describe Whois::Record::Parser::WhoisRegistryNetZa, "status_registered.expected" do

  subject do
    file = fixture("responses", "whois.registry.net.za/status_registered.txt")
    part = Whois::Record::Part.new(:body => File.read(file))
    described_class.new(part)
  end

  describe "#available?" do
    it do
      subject.available?.should be_false
    end
  end
  describe "#registered?" do
    it do
      subject.registered?.should == true
    end
  end
  describe "#nameservers" do
    it do
      subject.nameservers.should be_a(Array)
      subject.nameservers.should have(3).items
      subject.nameservers[0].should be_a(Whois::Record::Nameserver)
      subject.nameservers[0].name.should == "ns2.host-h.net"
      subject.nameservers[1].should be_a(Whois::Record::Nameserver)
      subject.nameservers[1].name.should == "ns1.dns-h.com"
      subject.nameservers[2].should be_a(Whois::Record::Nameserver)
      subject.nameservers[2].name.should == "ns1.host-h.net"
    end
  end
  describe "#registrar" do
    it do
      subject.registrar.should be_a(Whois::Record::Registrar)
      subject.registrar.id.should == "epag"
      subject.registrar.name.should == "EPAG Domainservices"
    end
  end
  describe "#registrant_contacts" do
    it do
      subject.registrant_contacts.should be_a(Array)
      subject.registrant_contacts.should have(1).items
      subject.registrant_contacts[0].should be_a(Whois::Record::Contact)
      subject.registrant_contacts[0].type.should         == Whois::Record::Contact::TYPE_REGISTRANT
      subject.registrant_contacts[0].name.should         == "Fred Flintstone"
      subject.registrant_contacts[0].email.should        == "someguy@somedomain.co.za"
      subject.registrant_contacts[0].phone.should        == "+27.219000000"
      subject.registrant_contacts[0].fax.should          == "+27.219001000"
      subject.registrant_contacts[0].address.should      == "30 Frazzita Business Park Durbanville Cape Town ZA 7550"
    end
  end
  describe "#domain" do
    it do
      subject.domain.should == "broccoliwafflesareawesome.co.za"
    end
  end
  describe "#created_on" do
    it do
      subject.created_on.should == Time.new(2012,3,27,nil,nil,nil,"+02:00")
    end
  end
  describe "#status" do
    it do
      subject.status.should == ['ok', 'autorenew']
    end
  end
  describe "#expires_on" do
    it do
      subject.expires_on.should == Time.new(2013,3,27,nil,nil,nil,"+02:00")
    end
  end
  describe "#disclaimer" do
    it do
      subject.disclaimer.should == "The use of this Whois facility is subject to the following terms and\nconditions. https://registry.net.za/whois_terms\nCopyright (c) UniForum SA 1995-2012\n"
    end
  end
  describe "#domain_id" do
    it do
      lambda { subject.domain_id }.should raise_error Whois::PropertyNotSupported
    end
  end
  describe "#referral_whois" do
    it do
      lambda { subject.referral_whois }.should raise_error Whois::PropertyNotSupported
    end
  end
  describe "#referral_url" do
    it do
      lambda { subject.referral_url }.should raise_error Whois::PropertyNotSupported
    end
  end
  describe "#updated_on" do
    it do
      lambda { subject.updated_on }.should raise_error Whois::PropertyNotSupported
    end
  end
  describe "#admin_contacts" do
    it do
      lambda { subject.admin_contacts }.should raise_error Whois::PropertyNotSupported
    end
  end
  describe "#technical_contacts" do
    it do
      lambda { subject.technical_contacts }.should raise_error Whois::PropertyNotSupported
    end
  end
end
