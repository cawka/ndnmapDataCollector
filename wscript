# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

from waflib import Logs, Utils
import os

def options(opt):
    opt.load(['compiler_cxx', 'gnu_dirs'])
    opt.load(['default-compiler-flags', 'boost', 'dependency-checker'],
             tooldir=['.waf-tools'])

def configure(conf):
    conf.load(['compiler_cxx', 'gnu_dirs',
               'default-compiler-flags', 'boost', 'dependency-checker'])

    if 'PKG_CONFIG_PATH' not in os.environ:
        os.environ['PKG_CONFIG_PATH'] = Utils.subst_vars('${LIBDIR}/pkgconfig', conf.env)
    conf.check_cfg(package='libndn-cxx', args=['--cflags', '--libs'],
                   uselib_store='NDN_CXX', mandatory=True)

    boost_libs = 'system'
    conf.check_boost(lib=boost_libs)
    if conf.env.BOOST_VERSION_NUMBER < 105800:
        conf.fatal('Minimum required Boost version is 1.58.0\n'
                   'Please upgrade your distribution or manually install a newer version of Boost'
                   ' (https://redmine.named-data.net/projects/nfd/wiki/Boost_FAQ)')

    conf.check_compiler_flags()

def build(bld):
    bld.program(target='ndnmapDataCollectorServer',
                source='ndnmapDataCollectorServer.cpp',
                use='NDN_CXX BOOST')

    bld.program(target='ndnmapDataCollectorClient',
                source='ndnmapDataCollectorClient.cpp',
                use='NDN_CXX BOOST')
