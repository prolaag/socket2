require "bundler/gem_tasks"

task :test do
  sh 'ruby ./test/internal.rb'
end

task :clean do
  rm_rf 'pkg'
  rm_r 'socket2-0.1.0.gem'
end

task :build do
  sh 'gem build socket2.gemspec'
end
