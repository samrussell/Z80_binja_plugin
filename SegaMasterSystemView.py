#!/usr/bin/env python

from struct import unpack

from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.types import Symbol
from binaryninja.enums import SegmentFlag, SymbolType, SectionSemantics

class SegaMasterSystemView(BinaryView):
	name = 'SMS'
	long_name = 'Sega Master System ROM'

	@classmethod
	def is_valid_cartridge_header(self, data):
		return data == b"TMR SEGA"

	@classmethod
	def is_valid_for_data(self, data):
		return self.is_valid_cartridge_header(data[0x7ff0:0x7ff8])

	def __init__(self, data):
		# data is a binaryninja.binaryview.BinaryView
		BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
		self.data = data

	def init(self):
		self.arch = Architecture['Z80']
		self.platform = Architecture['Z80'].standalone_platform

		# we need to add slots
		# we are starting on slot2 only games which means we can guarantee that the code isn't getting loaded in new places
		# and we can be really lazy and just load the first 3 slots

		# ram
		self.add_auto_segment(0xc000, 0x4000, 0, 0, SegmentFlag.SegmentReadable|SegmentFlag.SegmentWritable)

		# slot 0
		self.add_auto_segment(0x0, 0x4000, 0, 0x4000, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)

		# slot 1
		self.add_auto_segment(0x4000, 0x4000, 0x4000, 0x4000, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)

		# slot 2
		self.add_auto_segment(0x8000, 0x4000, 0x8000, 0x4000, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)

		# leave 0xc000 for ram and add slots after?

		self.add_auto_segment(0x10000, 0x100000, 0xc000, 0x100000, SegmentFlag.SegmentReadable)

		# workaround to disable linear sweep
		# but also we should mark the interrupt handlers
		self.add_user_section("entrypoint", 0x00, 0x8, SectionSemantics.ReadOnlyCodeSectionSemantics)

        # SMS ROMs start at $0000, add this and all interrupt handlers
		self.add_entry_point(0x00)
		self.add_entry_point(0x08)
		self.add_entry_point(0x10)
		self.add_entry_point(0x18)
		self.add_entry_point(0x20)
		self.add_entry_point(0x28)
		self.add_entry_point(0x30)
		self.add_entry_point(0x38)
		self.add_entry_point(0x66)

		return True

	def perform_is_executable(self):
		return True

	def perform_get_entry_point(self):
		return 0

	# undocumented but looks to match arch.address_size
	# so should be in bytes and should equal arch.address_size
	# but this breaks .synthetic_builtins when the rom mapping uses the whole memory
	# so we'll leave it at 8
	def perform_get_address_size(self):
		return 8
