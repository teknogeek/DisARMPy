from capstone import *
from elftools.elf.elffile import ELFFile
from Registers import Registers
import re

class DisARMPy:
    def __init__(self, filename):
        self.binary = filename
        self.file = open(filename, 'rb')
        self.data = self.file.read()

        self.elfFile = ELFFile(self.file)
        self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        self.registers = Registers()


    def disassemble(self):
        textSection = self.elfFile.get_section_by_name('.text')
        textData = textSection.data()
        
        self.registers.pc = textSection.header['sh_addr']
        self.registers.sp = textSection.header['sh_addr']
        
        for idx, i in enumerate(self.md.disasm(textData, self.registers.pc)):
            instruction = i.mnemonic
            options = i.op_str
            
            ilEquiv = self.generateIL(instruction, options)
            
            self.registers.pc += 4
            print('0x{:08x}\t\t{:<10}\t{:<40}\t{:<50}'.format(i.address, instruction, options, ilEquiv))
            
            if idx == 30:
                break
                
                
    def calculateRegisterSum(self, registers):
        value = 0
        for reg in registers:
            if not reg.startswith('#'):
                value += getattr(self.registers, reg)
            else:
                value += int(reg.replace('#', ''), 0)
        return value


    def generateIL(self, instruction, options):
        if instruction == 'ldr':
            # check for immediate offset, e.g. ldr r0, [pc, #4]
            offset = re.findall('\[([^\]]+)\]', options)
            
            # boolean for if pointer or not
            pointer = False
            if len(offset) > 0:
                # handle just the offset
                offset = offset[0]
                offsetList = map(str, offset.split(', '))
                
                value = self.calculateRegisterSum(offsetList)
                dest = options.replace(', [{}]'.format(offset), '')
                
                pointer = True
            else:
                args = options.split(', ')
                
                dest = args[0]
                value = getattr(self.registers, args[1])
                
            setattr(self.registers, dest, value)

            value = '0x{:x}'.format(value)
            if pointer:
                value = '*({})'.format(value)
                
            return '{} = {}'.format(dest, value)
        
        elif instruction == 'str':
            # check for immediate offset, e.g. str r0, [sp, #0x14]
            offset = re.findall('\[([^\]]+)\]', options)
            
            if len(offset) > 0:
                # handle just the offset
                offsetArg = str(offset[0])
                offsetList = offsetArg.split(', ')
                
                offset = ''
                baseAddr = offsetList[0]
                if len(offsetList) > 1:
                    offset = ' + {}'.format(int(offsetList[1].replace('#', ''), 0))
                    
                dest = '{}{}'.format(baseAddr, offset)
                value = options.replace(offsetArg, '').replace(', []', '')
            else:
                value, dest = options.split(', ')
                
            return '*({}) = {}'.format(dest, value)
        
        elif instruction in ['add', 'sub']:
            if instruction == 'sub':
                options = options.replace('#', '#-')
            
            args = options.split(', ')
            dest = args[0]
            value = self.calculateRegisterSum(args[1:])
            
            setattr(self.registers, dest, value)
            return '{} = 0x{:x}'.format(dest, value)
        
        elif instruction == 'andeq':
            args = options.split(', ')
           
            dest = args[0]
            del args[0]
            
            for idx, arg in enumerate(args):
                if hasattr(self.registers, arg):
                    args[idx] = getattr(self.registers, arg)
            
            value = args[0] & args[1]
            if 'lsl' in args[2]:
                value <<= int(args[2].replace('lsl #', ''), 0)
            
            setattr(self.registers, dest, value)
            return '{} = 0x{:x}'.format(dest, value)

        elif instruction == 'b':
            return 'goto 0x{:x}'.format(self.calculateRegisterSum([options]))
        
        elif instruction == 'push':
            # TODO: write push instruction
            return ''

        return 'PSUEDO CODE HERE'