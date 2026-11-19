-- Known-answer checks for the modules the fuzz targets drive (struct, sjson, bit) and the
-- compiler/VM. One result per line; mayhem/test.sh diffs them against kat_<lua>.expected.
local function hex(s) return (s:gsub('.', function(c) return string.format('%02x', c:byte()) end)) end
local load_text = loadstring or load
print('struct.pack', hex(struct.pack('<i2>I4', -2, 258)))
print('struct.unpack', struct.unpack('<h', '\254\255'))
print('struct.size', struct.size('<i4i2'))
print('struct.string', struct.unpack('c3', 'abcdef'))
print('struct.getnum_overflow', pcall(struct.unpack, 'c99999999999', 'x'))
print('sjson.decode', sjson.decode('{"a":[1,2,3],"b":"x\\u0041"}').b)
print('sjson.encode', sjson.encode({1, 2, 'x'}))
print('sjson.error', (pcall(sjson.decode, '{"a":')))
print('bit.band', bit.band(0xff, 0x0f), bit.bor(1, 4), bit.lshift(1, 8))
print('load', load_text('return 6*7')())
print('string', ('nodemcu'):upper():rep(2, '-'), #('x'):rep(100))
print('table', table.concat({3, 1, 2}, ','))
