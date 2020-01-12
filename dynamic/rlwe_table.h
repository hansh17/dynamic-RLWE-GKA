/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */

static uint64_t rlwe_table[52][3] = {
	{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x1FFFFFFFFFFFFFFF},
	{0xE0C81DA0D6A8BD22, 0x161ABD186DA13542, 0x5CEF2C248806C827},
	{0x8D026C4E14BC7408, 0x4344C125B3533F22, 0x9186506BCC065F20},
	{0x10AC7CEC7D7E2A3B, 0x5D62CE65E6217813, 0xBAAB5F82BCDB43B3},
	{0x709C92996E94D801, 0x1411F551608E4D22, 0xD7D9769FAD23BCB1},
	{0x6287D827008404B7, 0x7E1526D618902F20, 0xEA9BE2F4D6DDB5ED},
	{0x34CBDC118C15F40E, 0xE7D2A13787E94674, 0xF58A99474919B8C9},
	{0xD521F7EBBBE8C3A2, 0xE8A773D9A1EA0AAB, 0xFB5117812753B7B8},
	{0xC3D9E58131089A6A, 0x148CB49FF716491B, 0xFE151BD0928596D3},
	{0x2E060C4A842A27F6, 0x07E44D009ADB0049, 0xFF487508BA9F7208},
	{0xFCEDEFCFAA887582, 0x1A5409BF5D4B039E, 0xFFC16686270CFC82},
	{0x4FE22E5DF9FAAC20, 0xFDC99BFE0F991958, 0xFFEC8AC3C159431B},
	{0xA36605F81B14FEDF, 0xA6FCD4C13F4AFCE0, 0xFFFA7DF4B6E92C28},
	{0x9D1FDCFF97BBC957, 0x4B869C6286ED0BB5, 0xFFFE94BB4554B5AC},
	{0x6B3EEBA74AAD104B, 0xEC72329E974D63C7, 0xFFFFAADE1B1CAA95},
	{0x48C8DA4009C10760, 0x337F6316C1FF0A59, 0xFFFFEDDC1C6436DC},
	{0x84480A71312F35E7, 0xD95E7B2CD6933C97, 0xFFFFFC7C9DC2569A},
	{0x23C01DAC1513FA0F, 0x8E0B132AE72F729F, 0xFFFFFF61BC337FED},
	{0x90C89D6570165907, 0x05B9D725AAEA5CAD, 0xFFFFFFE6B3CF05F7},
	{0x692E2A94C500EC7D, 0x99E8F72C370F27A6, 0xFFFFFFFC53EA610E},
	{0x28C2998CEAE37CC8, 0xC6E2F0D7CAFA9AB8, 0xFFFFFFFF841943DE},
	{0xC515CF4CB0130256, 0x4745913CB4F9E4DD, 0xFFFFFFFFF12D07EC},
	{0x39F0ECEA047D6E3A, 0xEE62D42142AC6544, 0xFFFFFFFFFE63E348},
	{0xDF11BB25B50462D6, 0x064A0C6CC136E943, 0xFFFFFFFFFFD762C7},
	{0xCDBA0DD69FD2EA0F, 0xC672F3A74DB0F175, 0xFFFFFFFFFFFC5E37},
	{0xFDB966A75F3604D9, 0x6ABEF8B144723D83, 0xFFFFFFFFFFFFB48F},
	{0x3C4FECBB600740D1, 0x697598CEADD71A15, 0xFFFFFFFFFFFFFA72},
	{0x1574CC916D60E673, 0x12F5A30DD99D7051, 0xFFFFFFFFFFFFFFA1},
	{0xDD3DCD1B9CB7321D, 0x4016ED3E05883572, 0xFFFFFFFFFFFFFFFA},
	{0xB4A4E8CF3DF79A7A, 0xAF22D9AFAD5A73CF, 0xFFFFFFFFFFFFFFFF},
	{0x91056A8196F74466, 0xFBF88681905332BA, 0xFFFFFFFFFFFFFFFF},
	{0x965B9ED9BD366C04, 0xFFD16385AF29A51F, 0xFFFFFFFFFFFFFFFF},
	{0xF05F75D38F2D28A3, 0xFFFE16FF8EA2B60C, 0xFFFFFFFFFFFFFFFF},
	{0x77E35C8980421EE8, 0xFFFFEDD3C9DDC7E8, 0xFFFFFFFFFFFFFFFF},
	{0x92783617956F140A, 0xFFFFFF63392B6E8F, 0xFFFFFFFFFFFFFFFF},
	{0xA536DC994639AD78, 0xFFFFFFFB3592B3D1, 0xFFFFFFFFFFFFFFFF},
	{0x8F3A871874DD9FD5, 0xFFFFFFFFDE04A5BB, 0xFFFFFFFFFFFFFFFF},
	{0x310DE3650170B717, 0xFFFFFFFFFF257152, 0xFFFFFFFFFFFFFFFF},
	{0x1F21A853A422F8CC, 0xFFFFFFFFFFFB057B, 0xFFFFFFFFFFFFFFFF},
	{0x3CA9D5C6DB4EE2BA, 0xFFFFFFFFFFFFE5AD, 0xFFFFFFFFFFFFFFFF},
	{0xCFD9CE958E59869C, 0xFFFFFFFFFFFFFF81, 0xFFFFFFFFFFFFFFFF},
	{0xDB8E1F91D955C452, 0xFFFFFFFFFFFFFFFD, 0xFFFFFFFFFFFFFFFF},
	{0xF78EE3A8E99E08C3, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
	{0xFFE1D7858BABDA25, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
	{0xFFFF9E52E32CAB4A, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
	{0xFFFFFEE13217574F, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
	{0xFFFFFFFD04888041, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
	{0xFFFFFFFFF8CD8A56, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
	{0xFFFFFFFFFFF04111, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
	{0xFFFFFFFFFFFFE0C5, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
	{0xFFFFFFFFFFFFFFC7, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
	{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}
};
