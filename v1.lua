function dec2hex(input)
	return string.format('%X',tonumber(input));
end;

function randString(len)
	local ret = '';
	while(#ret <= len) do
		local byte = randSource:NextInteger(48,107);
		if(byte>=58 and byte<=83) then
			byte = byte + 7;
		elseif(byte>=84) then
			byte = byte + 13;
		end;
		ret = ret..string.char(byte);
	end;
	return ret;
end;

function explode(delim, input)
	if(input==nil) then
		local ret = {};
		for  i = 1, #delim do
			table.insert(ret,delim:sub(i,i));
		end;
		return ret;
	else
		local cinput, ret,cache = '',{},'';
		for  i = 1, #input do
			cinput = input:sub(i,i);
			if(cinput==delim) then
				table.insert(ret,cache);
				cache = '';
			elseif(cinput~='' and cinput~=' ') then
				cache = cache..cinput;
			end;
		end;
		if(cache~='' and cache~=' ') then
			table.insert(ret,cache);
		end;
		return ret;
	end;
end;

function encrypt(input, key)
	local input = explode(input);
	local iv1 = randString(16);
	local iv2 = randString(16);
	local key1 = key:sub(1,string.find(key,':')-1);
	local key2 = key:sub(string.find(key,':')+1);
	local ret,key1Index,key2Index,iv1Index,iv2Index = '',1,1,1,1;
	for  i = 1, #input do
		local inputByte = string.byte(input[i]);
		local key1Byte = string.byte(key1:sub(key1Index,key1Index));
		local key2Byte = string.byte(key2:sub(key2Index,key2Index));
		local iv1Byte = string.byte(iv1:sub(iv1Index,iv1Index));
		local iv2Byte = string.byte(iv2:sub(iv2Index,iv2Index));
		
		local step1 = bit32.bxor(inputByte,bit32.bxor(bit32.bxor(key2Byte,iv1Byte),iv2Byte));
		local step2 = bit32.lrotate(step1, 10);
		local step3 = bit32.bxor(step2,bit32.bxor(bit32.bxor(key1Byte,iv2Byte),iv1Byte));
		local step4 = bit32.lrotate(step3,10);
		local step5 = bit32.bxor(step4,(i-1));
		local step6 = bit32.lrotate(step5,10);
		local step7 = bit32.bxor(step6,bit32.bxor(bit32.bxor(key2Byte,iv1Byte),iv2Byte));
		
		ret = ret..dec2hex(step7)..':';
		
		key1Index = key1Index + 1; if(key1Index >= #key1) then key1Index = 1; end;
		key2Index = key2Index + 1; if(key2Index >= #key2) then key2Index = 1; end;
		iv1Index = iv1Index + 1; if(iv1Index >= #iv1) then iv1Index = 1; end;
		iv2Index = iv2Index + 1; if(iv2Index >= #iv2) then iv2Index = 1; end;
	end;
	return string.lower(ret:sub(1,#ret-1))..';'..iv1..';'..iv2;
end;

function decrypt(input, key)
	local ret,key1Index,key2Index,iv1Index,iv2Index = '',1,1,1,1;
	local key1 = key:sub(1,string.find(key,':')-1);
	local key2 = key:sub(string.find(key,':')+1);
	local iv1 = input:sub(string.find(input,';')+1,string.find(input,';',string.find(input,';')+5)-1);
	local iv2 = input:sub( string.find(input,';',string.find(input,';')+5)+1);
	local input = explode(':',input:sub(1,string.find(input,';')-1));

	for  i = 1, #input do
		local inputByte = tonumber('0x'..input[i]);
		local key1Byte = string.byte(key1:sub(key1Index,key1Index));
		local key2Byte = string.byte(key2:sub(key2Index,key2Index));
		local iv1Byte = string.byte(iv1:sub(iv1Index,iv1Index));
		local iv2Byte = string.byte(iv2:sub(iv2Index,iv2Index));
		
		local step7 = bit32.bxor(inputByte,bit32.bxor(bit32.bxor(key2Byte,iv1Byte),iv2Byte));
		local step6 = bit32.rrotate(step7, 10);
		local step5 = bit32.bxor(step6,(i-1));
		local step4 = bit32.rrotate(step5, 10);
		local step3 = bit32.bxor(step4,bit32.bxor(bit32.bxor(key1Byte,iv2Byte),iv1Byte));
		local step2 = bit32.rrotate(step3, 10);
		local step1 = bit32.bxor(step2,bit32.bxor(bit32.bxor(key2Byte,iv1Byte),iv2Byte));
		
		ret = ret..string.char(step1);
		
		key1Index = key1Index + 1; if(key1Index >= #key1) then key1Index = 1; end;
		key2Index = key2Index + 1; if(key2Index >= #key2) then key2Index = 1; end;
		iv1Index = iv1Index + 1; if(iv1Index >= #iv1) then iv1Index = 1; end;
		iv2Index = iv2Index + 1; if(iv2Index >= #iv2) then iv2Index = 1; end;
	end;
	return ret;
end;
