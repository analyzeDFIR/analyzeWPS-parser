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

try:
    from lib.parsers import ByteParser
    from lib.parsers.utils import StructureProperty
    from structures import wps as wpsstructs
except ImportError:
    from .lib.parsers import ByteParser
    from .lib.parsers.utils import StructureProperty
    from .structures import wps as wpsstructs

class OLETypedPropertyValue(ByteParser):
    '''
    Class for parsing an Object Linking and Embedding (OLE)
    Property Set typed property value structure
    '''
    value_type = StructureProperty(0, 'type')
    content = StructureProperty(1, 'content', deps=['type'])

    def _parse_content(self):
        '''
        Args:
            N/A
        Returns:
            Any
            Parsed value of type self.type
        Preconditions:
            N/A
        '''
        # TODO: Implement content parsers based on observed values in test examples
        return None
    def _parse_type(self):
        '''
        Args:
            N/A
        Returns:
            Integer
            Property value type (see structures.OLETypedPropertyValueTypes)
        Preconditions:
            N/A
        '''
        return wpsstructs.OLETypedPropertyValueTypes.parse_stream(self.stream)

class WPSPropertyValueInteger(ByteParser):
    '''
    Class for parsing Windows Property Store serialized property
    value (integer name) within a serialized property storage structure
    '''
    header = StructureProperty(0, 'header')
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
        if self.header.ValueSize == 0x00:
            return None
        # TODO: Make sure the arithmetic of stream size calculation is right
        return OLETypedPropertyValue(
            self.stream.getvalue()[self.stream.tell():( self.header.ValueSize - 4 )]
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
        return self._clean_value(
            wpsstructs.WPSPropertyValueIntegerNameHeader.parse_stream(self.stream)
        )

class WPSPropertyValueString(ByteParser):
    '''
    Class for parsing Windows Property Store serialized property
    value (string name) within a serialized property storage structure
    '''
    header = StructureProperty(0, 'header')
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
        return self._clean_value(
            wpsstructs.WPSPropertyValueStringNameHeader.parse_stream(self.stream)
        )

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
        while self.stream.tell() < ( self.header.Size + 4 ):
            original_position = self.stream.tell()
            property_value = property_value_class(self.stream.getvalue()[original_position:])
            property_value.parse()
            if property_value.header.ValueSize == 0x00:
                break
            self.stream.seek(original_position + property_value.header.ValueSize)
            property_value_list.append(property_value)
        return self._clean_value(property_value_list)
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
        return self._clean_value(wpsstructs.WPSPropertyStorageHeader.parse_stream(self.stream))

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
        while self.stream.tell() < self.header.Size:
            original_position = self.stream.tell()
            property_storage = WPSPropertyStorage(self.stream.getvalue()[original_position:])
            property_storage.parse()
            if property_storage.header.Size == 0x00:
                break
            self.stream.seek(original_position + property_storage.header.Size)
            property_storage_list.append(property_storage)
        return self._clean_value(property_storage_list)
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
        return self._clean_value(wpsstructs.WPSPropertyStoreHeader.parse_stream(self.stream))
