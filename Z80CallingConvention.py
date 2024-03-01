# Calling convention
from binaryninja import Architecture, CallingConvention

class DefaultCallingConvention(CallingConvention):
    caller_saved_regs = []
    int_arg_regs = []
    #int_return_reg = ''
    stack_adjusted_on_return = True
