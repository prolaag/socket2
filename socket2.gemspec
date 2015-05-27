# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'socket2'

Gem::Specification.new do |spec|
  spec.name          = "socket2"
  spec.version       = Socket2::VERSION
  spec.authors       = ["Prolaag"]
  spec.email         = ["prolaag@gmail.com"]

  spec.summary       = "Pure Ruby addition to Socket that allows layer-2 raw access in Linux"
  spec.description   = <<-EOT
    This pure Ruby addition to the Socket class provides a means of creating
    and manipulating layer-2 raw sockets. By default Ruby only provides native
    access to raw sockets at layer-3 (IP). This addition only supports
    Linux platforms.
  EOT
  spec.homepage      = "https://github.com/prolaag/socket2"
  spec.license       = "MIT"

  spec.files         = Dir.glob("lib/**/*") +
                       %w(README.md Gemfile LICENSE.txt socket2.gemspec)
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.9"
  spec.add_development_dependency "rake", "~> 10.0"
end
