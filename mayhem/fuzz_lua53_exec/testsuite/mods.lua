local p = pixbuf.newBuffer(4, 3) p:fill(1,2,3) local c = coroutine.wrap(function(a) local b = coroutine.yield(a+1) return b*2 end) return c(1), c(5), p:get(2)
