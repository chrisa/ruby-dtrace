#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'dtrace/provider'
require 'test/unit'

class TestDtraceProvider < Test::Unit::TestCase
  
  def test_massive_provider
    probecount = 2950
    Dtrace::Provider.create :test_massive1 do |p|
      (1 .. probecount).each do |i|
        p.probe "#{i}".to_sym
      end
    end
    
    t = Dtrace.new
    matches = 0
    t.each_probe("test_massive1#{$$}:ruby:test_massive_provider:") do |p|
      matches += 1
    end
    assert_equal probecount, matches
  end

  def test_provider_with_module
    Dtrace::Provider.create :test0, { :module => 'test1module' } do |p|
      p.probe :test
    end

    t = Dtrace.new
    matches = 0
    t.each_probe("test0#{$$}:test1module:test_provider_with_module:test") do |p|
      matches += 1
    end
    assert_equal 1, matches
  end

  def test_probe_with_function_no_args
    Dtrace::Provider.create :test10 do |p|
      p.probe :test, { :function => :foo }
    end

    t = Dtrace.new
    matches = 0
    t.each_probe("test10#{$$}:ruby:foo:test") do |p|
      matches += 1
    end
    assert_equal 1, matches
  end

  def test_probe_with_function_and_args
    Dtrace::Provider.create :test11 do |p|
      p.probe :test, { :function => :foo }, :integer, :integer
    end

    t = Dtrace.new
    matches = 0
    t.each_probe("test11#{$$}:ruby:foo:test") do |p|
      matches += 1
    end
    assert_equal 1, matches
  end

  def test_probe_no_args
    Dtrace::Provider.create :test1 do |p|
      p.probe :test
    end

    t = Dtrace.new
    matches = 0
    t.each_probe("test1#{$$}:ruby:test_probe_no_args:test") do |p|
      matches += 1
    end
    assert_equal 1, matches
  end

  def test_probe_with_char_arg
    Dtrace::Provider.create :test2 do |p|
      p.probe :test, :string
    end

    t = Dtrace.new
    matches = 0
    t.each_probe("test2#{$$}:ruby:test_probe_with_char_arg:test") do |p|
      matches += 1
    end
    assert_equal 1, matches
  end

  def test_probe_with_int_arg
    Dtrace::Provider.create :test3 do |p|
      p.probe :test, :integer
    end

    t = Dtrace.new
    matches = 0
    t.each_probe("test3#{$$}:ruby:test_probe_with_int_arg:test") do |p|
      matches += 1
    end
    assert_equal 1, matches
  end

  def test_probe_with_two_args
    Dtrace::Provider.create :test4 do |p|
      p.probe :test, :integer, :integer
    end

    t = Dtrace.new
    matches = 0
    t.each_probe("test4#{$$}:ruby:test_probe_with_two_args:test") do |p|
      matches += 1
    end
    assert_equal 1, matches
  end

  def test_multiple_probes_with_two_args
    Dtrace::Provider.create :test5 do |p|
      p.probe :test1, :integer, :integer
      p.probe :test2, :integer, :integer
    end

    t = Dtrace.new
    matches = 0
    t.each_probe("test5#{$$}:ruby:test_multiple_probes_with_two_args:") do |p|
      matches += 1
    end
    assert_equal 2, matches
  end

  def test_multiple_probes
    Dtrace::Provider.create :test6 do |p|
      p.probe :test1, :integer
      p.probe :test2, :integer
      p.probe :test3, :integer
      p.probe :test4, :integer
      p.probe :test5, :integer
    end

    t = Dtrace.new
    matches = 0
    t.each_probe("test6#{$$}:ruby:test_multiple_probes:") do |p|
      matches += 1
    end
    assert_equal 5, matches
  end

end

