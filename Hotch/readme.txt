Hotch 1.0.0 by Sebastian Porst (http://www.the-interweb.com)

1. Description

Hotch is binary file profiler for x86 files. Hotch is a plugin
for IDA Pro (http://www.hex-rays.com)

1. Installation

- Copy hotch.plw into IdaDir/plugins
- Copy template.htm to IdaDir/plugins/hotch

2. Use

- Load an x86 file into IDA Pro
- To profile the file from the entry point, start Hotch from the plugins menu.
- To profile some random part of the file, start the IDA debugger, run the target
  program and start Hotch whenever you want to.
- Shut down the debugger or the target process to stop profiling.
- Look at results.html in IdaDir/plugins/hotch

3. License

Hotch is licensed under the zlib/libpng license.

Copyright (c) 2008 Sebastian Porst

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
claim that you wrote the original software. If you use this software
in a product, an acknowledgment in the product documentation would be
appreciated but is not required.

2. Altered source versions must be plainly marked as such, and must not be
misrepresented as being the original software.

3. This notice may not be removed or altered from any source
distribution.