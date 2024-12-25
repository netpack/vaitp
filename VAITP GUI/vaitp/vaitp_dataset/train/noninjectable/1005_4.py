code = """
struct StructOne:
    a: String[33]
    b: uint256[3]

struct StructTwo:
    a: Bytes[5]
    b: int128[2]
    c: String[64]

a: public(StructOne)
b: public(uint256[2])
c: public(Bytes[32])
d: public(int128[4])
foo: public(HashMap[uint256, uint256[3]])
dyn_array: DynArray[uint256, 3]
e: public(String[47])
f: public(int256[1])
g: public(StructTwo[2])
h: public(int256[1])


@external
def __init__():
    self.a = StructOne({a: "ok", b: [4,5,6]})
    self.b = [7, 8]
    self.c = b"thisisthirtytwobytesokhowdoyoudo"
    self.d = [-1, -2, -3, -4]
    self.e = "A realllllly long string but we wont use it all"
    self.f = [33]
    self.g = [
        StructTwo({a: b"hello", b: [-66, 420], c: "another string"}),
        StructTwo({
            a: b"gbye",
            b: [1337, 888],
            c: "whatifthisstringtakesuptheentirelengthwouldthatbesobadidothinkso"
        })
    ]
    self.dyn_array = [1, 2, 3]
    self.h =  [123456789]
    self.foo[0] = [987, 654, 321]
    self.foo[1] = [123, 456, 789]

@external
@nonreentrant('lock')
def with_lock():
    pass


@external
@nonreentrant('otherlock')
def with_other_lock():
    pass
"""