namespace :dtrace do

  desc 'Set up dtrace in your rails application'
  task :setup do
    ['dtracer'].each do |script|
      script_dest = "#{RAILS_ROOT}/script/#{script}"
      script_src = File.dirname(__FILE__) + "/../bin/#{script}.rb"
      
      FileUtils.chmod 0774, script_src
      
      unless File.exists?(script_dest)
        puts "Copying acts_as_encrypted script #{script}.rb to #{script_dest}"
        FileUtils.cp_r(script_src, script_dest)
      end
    end

    ['stylesheets/dtrace.css'].each do |asset|
      asset_dest = "#{RAILS_ROOT}/public/#{asset}"
      asset_src = File.dirname(__FILE__) + "/../public/#{asset}"
      
      FileUtils.chmod 0774, asset_src
      
      unless File.exists?(asset_dest)
        puts "Copying acts_as_encrypted asset #{asset} to #{asset_dest}"
        FileUtils.cp_r(asset_src, asset_dest)
      end
    end
  end
  
  desc 'Remove dtrace from your rails application'
  task :remove do 
    ['dtracer'].each do |script|
      script_dest = "#{RAILS_ROOT}/script/#{script}"

      if File.exists?(script_dest)
        puts "Removing #{script_dest} ..."
        FileUtils.rm(script_dest, :force => true)
      end
    end

    ['stylesheets/dtrace.css'].each do |asset|
      asset_dest = "#{RAILS_ROOT}/public/#{asset}"

      if File.exists?(asset_dest)
        puts "Removing #{asset_dest} ..."
        FileUtils.rm(asset_dest, :force => true)
      end
    end
  end

end
    
