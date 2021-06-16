#include <config.h>

#include "virarch.h"
#include "virbitmap.h"
#include "virt-host-validate-ch.h"
#include "virt-host-validate-common.h"

int virHostValidateCh(void) {
  int ret = 0;
  virBitmap *flags;
  bool hasHwVirt = false;
  bool hasVirtFlag = false;
  virArch arch = virArchFromHost();
  const char *kvmhint =
      _("Check that CPU and firmware supports CH virtualization "
        "and kvm module is loaded");

  if (!(flags = virHostValidateGetCPUFlags()))
    return -1;

  // Unlick QEMU, Cloud-Hypervisor only supports x86_64 and aarch64
  switch ((int)arch) {
  case VIR_ARCH_X86_64:
    hasVirtFlag = true;
    kvmhint = _("Check that the 'kvm-intel' or 'kvm-amd' modules are "
                "loaded & the BIOS has enabled virtualization");
    if (virBitmapIsBitSet(flags, VIR_HOST_VALIDATE_CPU_FLAG_SVM) ||
        virBitmapIsBitSet(flags, VIR_HOST_VALIDATE_CPU_FLAG_VMX))
      hasHwVirt = true;
    break;
  case VIR_ARCH_AARCH64:
    hasVirtFlag = true;
    hasHwVirt = true;
    break;
  default:
    hasHwVirt = false;
    break;
  }

  if (hasVirtFlag) {
    virHostMsgCheck("CH", "%s", _("for hardware virtualization"));
    if (hasHwVirt) {
      virHostMsgPass();
    } else {
      virHostMsgFail(VIR_HOST_VALIDATE_FAIL,
                     _("Only emulated CPUs are available, performance will be "
                       "significantly limited"));
      ret = -1;
    }
  }

  if (hasHwVirt || !hasVirtFlag) {
    if (virHostValidateDeviceExists("CH", "/dev/kvm", VIR_HOST_VALIDATE_FAIL,
                                    kvmhint) < 0)
      ret = -1;
    else if (virHostValidateDeviceAccessible(
                 "CH", "/dev/kvm", VIR_HOST_VALIDATE_FAIL,
                 _("Check /dev/kvm is world writable or you are in "
                   "a group that is allowed to access it")) < 0)
      ret = -1;
  }

  return ret;
}
