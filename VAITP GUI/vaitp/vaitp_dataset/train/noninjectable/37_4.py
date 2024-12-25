def I16(ptr):
    return ptr[0] + (ptr[1] << 8)

def I32(ptr):
    return ptr[0] + (ptr[1] << 8) + (ptr[2] << 16) + (ptr[3] << 24)

def ImagingFliDecode(im, state, buf, bytes):
    ptr = buf
    if bytes < 4:
        return 0

    framesize = I32(ptr)
    if framesize < I32(ptr):
        return 0
    if bytes < 8:
        state['errcode'] = "IMAGING_CODEC_OVERRUN"
        return -1
    if I16(ptr[4:]) != 0xF1FA:
        state['errcode'] = "IMAGING_CODEC_UNKNOWN"
        return -1

    chunks = I16(ptr[6:])
    ptr = ptr[16:]
    bytes -= 16

    for c in range(chunks):
        if bytes < 10:
            state['errcode'] = "IMAGING_CODEC_OVERRUN"
            return -1
        data = ptr[6:]
        chunk_type = I16(ptr[4:])

        if chunk_type == 4 or chunk_type == 11:
            pass # FLI COLOR chunk
        elif chunk_type == 7: #FLI SS2 chunk (word delta)
            lines = I16(data)
            data = data[2:]
            y = 0
            for l in range(lines):
                if y >= state['ysize']:
                    break
                local_buf = im['image'][y]
                
                if len(data) < 2:
                    state['errcode'] = "IMAGING_CODEC_OVERRUN"
                    return -1
                packets = I16(data)
                data = data[2:]

                while packets & 0x8000:
                    if packets & 0x4000:
                        y += 65536 - packets
                        if y >= state['ysize']:
                             state['errcode'] = "IMAGING_CODEC_OVERRUN"
                             return -1
                        local_buf = im['image'][y]
                    else:
                         local_buf[state['xsize'] - 1] = (packets) & 0xFF
                    if len(data) < 2:
                        state['errcode'] = "IMAGING_CODEC_OVERRUN"
                        return -1
                    packets = I16(data)
                    data = data[2:]
                x = 0
                p = 0
                while p < packets:
                    if len(data) < 2:
                         state['errcode'] = "IMAGING_CODEC_OVERRUN"
                         return -1
                    x += data[0]
                    if data[1] >= 128:
                         if len(data) < 4:
                             state['errcode'] = "IMAGING_CODEC_OVERRUN"
                             return -1
                         i = 256 - data[1]
                         if x + i + i > state['xsize']:
                             break
                         for j in range(i):
                             local_buf[x] = data[2]
                             x+=1
                             local_buf[x] = data[3]
                             x +=1
                         data = data[4:]
                    else:
                         i = 2 * data[1]
                         if x + i > state['xsize']:
                            break
                         if len(data) < 2 + i:
                            state['errcode'] = "IMAGING_CODEC_OVERRUN"
                            return -1
                         for k in range(i):
                            local_buf[x+k] = data[2+k]

                         x += i
                         data = data[2+i:]
                    p +=1
                if p < packets:
                     break

                y += 1
            if l < lines:
                state['errcode'] = "IMAGING_CODEC_OVERRUN"
                return -1


        elif chunk_type == 12: #FLI LC chunk (byte delta)
            y = I16(data)
            ymax = y + I16(data[2:])
            data = data[4:]
            while y < ymax and y < state['ysize']:
                out = im['image'][y]
                if len(data) < 1:
                    state['errcode'] = "IMAGING_CODEC_OVERRUN"
                    return -1
                packets = data[0]
                data = data[1:]
                x = 0
                p = 0
                while p < packets:
                     if len(data) < 2:
                         state['errcode'] = "IMAGING_CODEC_OVERRUN"
                         return -1
                     x += data[0]
                     if data[1] & 0x80:
                            i = 256 - data[1]
                            if x + i > state['xsize']:
                                break
                            if len(data) < 3:
                                 state['errcode'] = "IMAGING_CODEC_OVERRUN"
                                 return -1
                            for k in range(i):
                                out[x+k] = data[2]
                            data = data[3:]
                     else:
                         i = data[1]
                         if x + i > state['xsize']:
                            break
                         if len(data) < 2 + i:
                            state['errcode'] = "IMAGING_CODEC_OVERRUN"
                            return -1

                         for k in range(i):
                             out[x+k] = data[2+k]

                         data = data[2+i:]

                     p +=1

                if p < packets:
                        break
                y += 1

            if y < ymax:
                state['errcode'] = "IMAGING_CODEC_OVERRUN"
                return -1

        elif chunk_type == 13:
            for y in range(state['ysize']):
                im['image'][y] = [0] * state['xsize']

        elif chunk_type == 15: #FLI BRUN chunk
            for y in range(state['ysize']):
                out = im['image'][y]
                data = data[1:]
                x = 0
                while x < state['xsize']:
                    if len(data) < 2:
                         state['errcode'] = "IMAGING_CODEC_OVERRUN"
                         return -1
                    if data[0] & 0x80:
                        i = 256 - data[0]
                        if x + i > state['xsize']:
                             break
                        if len(data) < 1+i:
                            state['errcode'] = "IMAGING_CODEC_OVERRUN"
                            return -1
                        for k in range(i):
                            out[x+k] = data[1+k]
                        data = data[1+i:]

                    else:
                        i = data[0]
                        if x+i > state['xsize']:
                           break
                        for k in range(i):
                            out[x+k] = data[1]
                        data = data[2:]

                    x += i
                if x != state['xsize']:
                    state['errcode'] = "IMAGING_CODEC_OVERRUN"
                    return -1

        elif chunk_type == 16:
            if state['xsize'] > bytes // state['ysize']:
                return ptr - buf
            for y in range(state['ysize']):
                local_buf = im['image'][y]
                local_buf[:state['xsize']] = data[:state['xsize']]
                data = data[state['xsize']:]
        elif chunk_type == 18:
             pass
        else:
             state['errcode'] = "IMAGING_CODEC_UNKNOWN"
             return -1
        advance = I32(ptr)
        if advance < 0 or advance > bytes:
            state['errcode'] = "IMAGING_CODEC_OVERRUN"
            return -1
        ptr = ptr[advance:]
        bytes -= advance
    return -1