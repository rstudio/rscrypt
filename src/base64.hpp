#ifndef BASE64_H
#define BASE64_H

void encodeblock( unsigned char in[3], unsigned char out[4], int len );
void decodeblock( unsigned char in[4], unsigned char out[3], int len );

template <class InputIterator>
std::string b64encode(InputIterator begin, InputIterator end)
{
    unsigned char in[3], out[4];
    int i, len;

    std::string databuf;

    while( begin != end ) {
        len = 0;
        for( i = 0; i < 3; i++ ) {
            if( begin != end ) {
                in[i] = static_cast<unsigned char>( *begin++ );
                len++;
            } else {
                in[i] = 0;
            }
        }
        if( len ) {
            encodeblock( in, out, len );
            for( i = 0; i < 4; i++ ) {
                databuf.push_back(out[i]);
            }
        }
    }
    return databuf;
}

template <class InputIterator>
std::string b64decode(InputIterator begin, InputIterator end)
{
    unsigned char in[4], out[3];
    unsigned char tmp;
    int i, len;

    std::string databuf;

    while( begin != end ) {
        len = 0;
        for( i = 0; i < 4; i++ ) {
            if( begin != end ) {
                tmp = static_cast<unsigned char>( *begin++ );
                if (tmp != '=') {
                    in[i] = tmp;
                    len++;
                } else {
                    in[i] = 0;
                }
            } else {
                in[i] = 0;
            }
        }
        if( len ) {
            decodeblock( in, out, len );
            for( i = 0; i < 3; i++ ) {
                databuf.push_back(out[i]);
            }
        }
    }
    return databuf;
}

#endif
