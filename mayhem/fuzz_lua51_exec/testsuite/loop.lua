local t={} for i=1,100 do t[i]=i*i end
local s=0 for _,v in ipairs(t) do s=s+v end
return string.format("%d %s", s, sjson.encode(t))
