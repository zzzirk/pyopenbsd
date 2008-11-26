import shutil, os
from distutils.core import setup, Extension
from distutils.command import build_scripts

class MyBuildScripts(build_scripts.build_scripts):
    """
        This class extends the normal distutils to copy install scripts minus
        their .py extensions. That is, a script "foo.py" would be installed as
        simply "foo".
    """
    def copy_scripts(self):
        copies = []
        for i in self.scripts:
            if os.path.exists(i + ".py"):
                shutil.copyfile(i + ".py", i)
                copies.append(i)
        build_scripts.build_scripts.copy_scripts(self)
        for i in copies:
            os.remove(i)


CFLAGS=["-Wall"]

arc4random  = Extension(
                           "openbsd.arc4random",
                            sources = ["openbsd/arc4random.c"],
                            extra_compile_args=CFLAGS
                       )
netstat     = Extension(
                            "openbsd._netstat",
                            sources = ["openbsd/_netstat.c", "openbsd/_kvm.c", "openbsd/_cutils.c"],
                            libraries = ["kvm"],
                            extra_compile_args=CFLAGS
                       )
sysvar      = Extension(
                            "openbsd._sysvar",
                            sources = ["openbsd/_sysvar.c"],
                            extra_compile_args=CFLAGS
                       )
ifconfig      = Extension(
                            "openbsd._ifconfig",
                            sources = ["openbsd/_ifconfig.c", "openbsd/_cutils.c"],
                            extra_compile_args=CFLAGS
                       )
kqueue      = Extension(
                            "openbsd._kqueue",
                            sources = ["openbsd/_kqueue.c"],
                            extra_compile_args=CFLAGS
                       )
pf          = Extension(
                            "openbsd._pf",
                            sources = ["openbsd/_pf.c", "openbsd/_cutils.c"],
                            extra_compile_args=CFLAGS
                        )
system       = Extension(
                            "openbsd._system",
                            sources = ["openbsd/_system.c", "openbsd/_cutils.c"],
                            extra_compile_args=CFLAGS
                        )

setup (
        name = 'Python OpenBSD bindings',
        version = '0.1.1',
        description = 'An extensive set of Python bindings for OpenBSD-specific libraries.',
        ext_modules = [arc4random, sysvar, netstat, ifconfig, kqueue, pf, system],
        packages=["openbsd"],
       cmdclass = {"build_scripts": MyBuildScripts}
    )
