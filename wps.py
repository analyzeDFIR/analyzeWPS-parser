## -*- coding: UTF-8 -*-
## wps.py
##
## Copyright (c) 2018 analyzeDFIR
## 
## Permission is hereby granted, free of charge, to any person obtaining a copy
## of this software and associated documentation files (the "Software"), to deal
## in the Software without restriction, including without limitation the rights
## to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
## copies of the Software, and to permit persons to whom the Software is
## furnished to do so, subject to the following conditions:
## 
## The above copyright notice and this permission notice shall be included in all
## copies or substantial portions of the Software.
## 
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
## IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
## FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
## AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
## LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
## OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
## SOFTWARE.

import logging
Logger = logging.getLogger(__name__)

try:
    from lib.parsers import ByteParser
    from lib.parsers.utils import StructureProperty
    from lib.oleps import OLETypedPropertyValue
    from structures import wps as wpsstructs
except ImportError:
    from .lib.parsers import ByteParser
    from .lib.parsers.utils import StructureProperty
    from .lib.oleps import OLETypedPropertyValue
    from .structures import wps as wpsstructs

class WPSPropertyValue(ByteParser):
    '''
    Base class for WPS Property Values (name, integer) that
    implements check for header ValueSize as 0x00
    '''
    header = StructureProperty(0, 'header')

    def _parse_continue(self, structure, result):
        '''
        @ByteParser._parse_continue
        '''
        if not super()._parse_continue(structure, result):
            return False
        return not (structure == 'header' and self.header.ValueSize == 0x00)

class WPSPropertyValueInteger(WPSPropertyValue):
    '''
    Class for parsing Windows Property Store serialized property
    value (integer name) within a serialized property storage structure
    '''
    value = StructureProperty(1, 'value', deps=['header'])

    def _parse_value(self):
        '''
        Args:
            N/A
        Returns:
            OLETypedPropertyValue
            Typed property value
        Preconditions:
            N/A
        '''
        return OLETypedPropertyValue(
            self.source[self.stream.tell():( self.header.ValueSize )]
        ).parse()
    def _parse_header(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            Property value (integer name) header 
            (see structures.WPSPropertyValueIntegerNameHeader)
        Preconditions:
            N/A
        '''
        return wpsstructs.WPSPropertyValueIntegerNameHeader.parse_stream(self.stream)

class WPSPropertyValueString(WPSPropertyValue):
    '''
    Class for parsing Windows Property Store serialized property
    value (string name) within a serialized property storage structure
    '''
    name = StructureProperty(1, 'name', deps=['header'])
    value = StructureProperty(2, 'value', deps=['header'])

    def _parse_value(self):
        '''
        Args:
            N/A
        Returns:
            OLETypedPropertyValue
            Typed property value
        Preconditions:
            N/A
        '''
        return WPSPropertyValueInteger._parse_value(self)
    def _parse_name(self):
        '''
        Args:
            N/A
        Returns:
            String
            Name of this property value
        Preconditions:
            N/A
        '''
        # TODO: Check to see if this works, has been ( length * 2 ).decode('UTF16') for other parsers
        return self.stream.read(self.header.NameSize).decode('UTF16')
    def _parse_header(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            Property value (string name) header 
            (see structures.WPSPropertyValueIntegerNameHeader)
        Preconditions:
            N/A
        '''
        return wpsstructs.WPSPropertyValueStringNameHeader.parse_stream(self.stream)

class WPSPropertyStorage(ByteParser):
    '''
    Class for parsing Windows Property Store serialized property
    storage structure
    '''
    header = StructureProperty(0, 'header')
    property_value_list = StructureProperty(1, 'property_value_list', deps=['header'])

    def _parse_property_value_list(self):
        '''
        Args:
            N/A
        Returns:
            List<WPSPropertyValue{String,Integer}>
            List of property value structures
        Preconditions:
            N/A
        '''
        property_value_list = list()
        if (
            self.header.FormatID.Group1 == 0xD5CDD505 and \
            self.header.FormatID.Group2 == 0x2E9C and \
            self.header.FormatID.Group3 == 0x101B and \
            self.header.FormatID.Group4 == 0x9397 and \
            self.header.FormatID.Group5 == 0x08002B2CF9AE 
        ):
            property_value_class = WPSPropertyValueString
        else:
            property_value_class = WPSPropertyValueInteger
        while self.stream.tell() < self.header.Size:
            original_position = self.stream.tell()
            property_value = property_value_class(self.source[original_position:])
            property_value.parse()
            if property_value.header.ValueSize == 0x00:
                break
            self.stream.seek(original_position + property_value.header.ValueSize)
            property_value_list.append(property_value)
        return property_value_list
    def _parse_header(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            Windows Property Store property storage header (see structures.WPSPropertyStorageHeader)
        Preconditions:
            N/A
        '''
        return wpsstructs.WPSPropertyStorageHeader.parse_stream(self.stream)

class WPS(ByteParser):
    '''
    Class for parsing Windows Property Store structure
    '''
    header = StructureProperty(0, 'header')
    property_storage_list = StructureProperty(1, 'property_storage_list', deps=['header'])

    def _parse_property_storage_list(self):
        '''
        Args:
            N/A
        Returns:
            List<WPSPropertyStorage>
            List of property storage structures
        Preconditions:
            N/A
        '''
        property_storage_list = list()
        while self.stream.tell() < ( self.header.Size - 0x04 ):
            original_position = self.stream.tell()
            property_storage = WPSPropertyStorage(self.source[original_position:])
            property_storage.parse()
            if property_storage.header.Size == 0x00:
                break
            self.stream.seek(original_position + property_storage.header.Size)
            property_storage_list.append(property_storage)
        return property_storage_list
    def _parse_header(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            Windows Property Store header (see structures.WPSPropertyStoreHeader)
        Preconditions:
            N/A
        '''
        return wpsstructs.WPSPropertyStoreHeader.parse_stream(self.stream)
