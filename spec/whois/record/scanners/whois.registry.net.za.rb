# encoding: utf-8

require "spec_helper"
require File.join(SPEC_ROOT, "..", "lib", "whois", "record", "scanners", "whois.registry.net.za")
# require 'whois/record/scanners/whois.registry.net.za.rb'

describe Whois::Record::Scanners::WhoisRegistryNetZa do
  subject do
    file = fixture("responses", "whois.registry.net.za/status_registered.txt")
    Whois::Record::Scanners::WhoisRegistryNetZa.new(IO.read(file))
  end

  it "exists!" do
    described_class.should < Whois::Record::Scanners::Base
  end

  it "parses the domain name" do
    subject.parse[:domain_name].should eq "broccoliwafflesareawesome.co.za"
  end

  it "parses out the registrant's name" do
    subject.parse[:registrant_name].should eq "Fred Flintstone"
  end

  it "parses out the registrant's email" do
    subject.parse[:registrant_email].should eq "someguy@somedomain.co.za"
  end

  it "parses out the registrant's telephone number" do
    subject.parse[:registrant_telephone].should eq "+27.219000000"
  end

  it "parses out the registrant's fax number" do
    subject.parse[:registrant_fax].should eq "+27.219001000"
  end

  it "parses out the registrant's address" do
    subject.parse[:registrant_address].should eq "30 Frazzita Business Park Durbanville Cape Town ZA 7550"
  end

  it "parses out the registrar's name" do
    subject.parse[:registrar_name].should eq "EPAG Domainservices"
  end
end
