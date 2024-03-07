import binaryninja

from .Z80Arch import Z80
Z80.register()

from .Z80CallingConvention import DefaultCallingConvention
binaryninja.Architecture['Z80'].register_calling_convention(DefaultCallingConvention(binaryninja.Architecture['Z80'], 'default'))

from .Z80Workflows import optimize16bitloads, propagate_akku, split_subregs

wf = binaryninja.Workflow().clone("Optimize16BitLoadsWorkflow")

wf.register_activity(binaryninja.Activity("extension.smsworkflow.optimize16bitloads", action=optimize16bitloads))
wf.register_activity(binaryninja.Activity("extension.smsworkflow.propagateakku", action=propagate_akku))
wf.insert("core.function.analyzeTailCalls", ["extension.smsworkflow.propagateakku", "extension.smsworkflow.optimize16bitloads"])

# doesn't work until we can insert LLIL at the start of the function
# wf.register_activity(binaryninja.Activity("extension.popretworkflow.split_subregs", action=split_subregs))
# wf.insert("core.function.generateMediumLevelIL", ["extension.popretworkflow.split_subregs"])

wf.register()

from .ColecoView import ColecoView
ColecoView.register()

from .RelView import RelView
RelView.register()

from .SegaMasterSystemView import SegaMasterSystemView
SegaMasterSystemView.register()

# built-in view
EM_Z80 = 220
binaryninja.BinaryViewType['ELF'].register_arch(EM_Z80, binaryninja.enums.Endianness.LittleEndian, binaryninja.Architecture['Z80'])


