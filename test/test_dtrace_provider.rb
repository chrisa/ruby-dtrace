#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'dtrace/provider'
require 'test/unit'

class TestDtraceProvider < Test::Unit::TestCase
  
  def test_provider_with_module
    Dtrace::Provider.create :test0, { :module => 'test1module' } do |p|
      p.probe :test
    end

    t = Dtrace.new
    matches = 0
    t.each_probe do |p|
      if p.to_s == "test0#{$$}:test1module:main:test"
        matches += 1
      end
    end
    assert_equal 1, matches
  end

  def test_probe_with_function_no_args
    Dtrace::Provider.create :test10 do |p|
      p.probe :test, { :function => :foo }
    end

    t = Dtrace.new
    matches = 0
    t.each_probe do |p|
      if p.to_s == "test10#{$$}:ruby:foo:test"
        matches += 1
      end
    end
    assert_equal 1, matches
  end

  def test_probe_with_function_and_args
    Dtrace::Provider.create :test11 do |p|
      p.probe :test, { :function => :foo }, :integer, :integer
    end

    t = Dtrace.new
    matches = 0
    t.each_probe do |p|
      if p.to_s == "test11#{$$}:ruby:foo:test"
        matches += 1
      end
    end
    assert_equal 1, matches
  end

  def test_probe_no_args
    Dtrace::Provider.create :test1 do |p|
      p.probe :test
    end

    t = Dtrace.new
    matches = 0
    t.each_probe do |p|
      if p.to_s == "test1#{$$}:ruby:main:test"
        matches += 1
      end
    end
    assert_equal 1, matches
  end

  def test_probe_with_char_arg
    Dtrace::Provider.create :test2 do |p|
      p.probe :test, :string
    end

    t = Dtrace.new
    matches = 0
    t.each_probe do |p|
      if p.to_s == "test2#{$$}:ruby:main:test"
        matches += 1
      end
    end
    assert_equal 1, matches
  end

  def test_probe_with_int_arg
    Dtrace::Provider.create :test3 do |p|
      p.probe :test, :integer
    end

    t = Dtrace.new
    matches = 0
    t.each_probe do |p|
      if p.to_s == "test3#{$$}:ruby:main:test"
        matches += 1
      end
    end
    assert_equal 1, matches
  end

  def test_probe_with_two_args
    Dtrace::Provider.create :test4 do |p|
      p.probe :test, :integer, :integer
    end

    t = Dtrace.new
    matches = 0
    t.each_probe do |p|
      if p.to_s == "test4#{$$}:ruby:main:test"
        matches += 1
      end
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
    t.each_probe do |p|
      if p.to_s =~ /^test5#{$$}:ruby:main:test/
        matches += 1
      end
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
    t.each_probe do |p|
      if p.to_s =~ /^test6#{$$}:ruby:main:test/
        matches += 1
      end
    end
    assert_equal 5, matches
  end

end

