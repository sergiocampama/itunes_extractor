# Extract playlists from a non-XML iTunes Library file (.itl)
# Copyright (c) 2018 Benno Rice, released under the BSD (2 Clause) Licence.

# Important information on the encryption used in the .itl file found here:
# https://mrexodia.cf/reversing/2014/12/16/iTunes-Library-Format-1
# Highly useful information on the .itl format itself found here:
# https://github.com/josephw/titl/blob/master/titl-core/src/main/java/org/kafsemo/titl/ParseLibrary.java

import argparse
import collections
import csv
import enum
import io
import struct
import zlib
from urllib.parse import unquote
import unicodedata

from Crypto.Cipher import AES


HEADER_LENGTH = 0x90
CRYPTO_KEY = b'BHUILuilfghuila3'


Hdfm = collections.namedtuple('Hdfm', field_names=[
    'file_length',
    'version',
])

Hdsm = collections.namedtuple('Hdsm', field_names=[
    'block_type',
    'block_length',
])

Hghm = collections.namedtuple('Hghm', field_names=[])

Hohm = collections.namedtuple('Hohm', field_names=[
    'record_length',
    'type',
    'data',
])

Halm = collections.namedtuple('Hghm', field_names=[])

Haim = collections.namedtuple('Haim', field_names=[])

Hilm = collections.namedtuple('Hilm', field_names=[])

Hiim = collections.namedtuple('Hiim', field_names=[])

Htlm = collections.namedtuple('Htlm', field_names=[])

Htim = collections.namedtuple('Htim', field_names=[
    'record_length',
    'sub_blocks',
    'song_id',
    'block_type',
    # 'file_type',
    # 'playtime',
    # 'track_number',
    # 'track_total',
    # 'year',
    # 'bit_rate',
    # 'sample_rate',
    # 'volume_adjustment',
    # 'start_time',
    # 'end_time',
    # 'play_count',
    # 'compilation',
    # 'last_played',
    # 'disk_number',
    # 'disk_total',
    # 'rating',
    # 'added',
])

Hqlm = collections.namedtuple('Hqlm', field_names=[])

Hqim = collections.namedtuple('Hqlm', field_names=[])

Hsts = collections.namedtuple('Hsts', field_names=[])

Hplm = collections.namedtuple('Hplm', field_names=[])

Hpim = collections.namedtuple('Hpim', field_names=[
    'item_count',
])

Hptm = collections.namedtuple('Hptm', field_names=[
    'key',
])

Hslm = collections.namedtuple('Hslm', field_names=[])

Hpsm = collections.namedtuple('Hpsm', field_names=[])

Hrlm = collections.namedtuple('Hrlm', field_names=[])

Hrpm = collections.namedtuple('Hrpm', field_names=[])


class HohmType(enum.IntEnum):
    TITLE = 0x02
    ALBUM_TITLE = 0x03
    ARTIST = 0x04
    PLAYLIST_TITLE = 0x64
    LOCAL_PATH = 0xb


HOHM_ODD_TYPES = (0x42, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x192, 0x1f7, 0x1f4, 0x202, 0x320)


class ItlIO(io.BytesIO):
    def __init__(self, *args, **kwargs):
        self.flipped = False
        super().__init__(*args, **kwargs)

    def skip(self, nbytes):
        self.read(nbytes)

    def read_ascii(self, nbytes):
        return self.read(nbytes).decode('ascii')

    def read_byte(self):
        return self.read(1)[0]

    def read_uint(self):
        if self.flipped:
            return struct.unpack('<I', self.read(4))[0]
        else:
            return struct.unpack('>I', self.read(4))[0]


class RecordParser:
    def __init__(self, data):
        self.data = ItlIO(data)

    def parse(self):
        while True:
            record_type = self.data.read_ascii(4)
            original_type = record_type
            if not record_type:
                return

            if self.data.flipped:
                record_type = record_type[-1::-1]

            method = f'parse_{record_type}'

            # print(original_type)

            if not hasattr(self, method):
                method = f'parse_{record_type[-1::-1]}'
                if not hasattr(self, method):
                    # print(record_type, self.data.getvalue()[self.data.tell():])
                    raise ValueError(f"unknown record type: {record_type}")
                self.data.flipped = True

            length = self.data.read_uint() - 8
            # print(length)
            read_data = self.data.read(length)
            data = ItlIO(read_data)
            # print(read_data)
            if self.data.flipped:
                data.flipped = True
            yield getattr(self, method)(data)

    def parse_hdfm(self, data):
        file_length = data.read_uint()
        data.skip(4)
        version_length = data.read_byte()
        version = data.read_ascii(version_length)
        return Hdfm(file_length=file_length,
                    version=version)

    def parse_hdsm(self, data):
        record_length = data.read_uint()
        block_type = data.read_uint()

        if block_type in (4, 22):
            self.data.skip(record_length - len(data.getvalue()) - 8)

        return Hdsm(block_type=block_type, block_length=record_length)

    def parse_hghm(self, data):
        return Hghm()

    def parse_hohm(self, data):
        record_length = data.read_uint()
        hohm_type = data.read_uint()
        hohm_data = self.data.read(record_length - len(data.getvalue()) - 8)

        # print(hex(hohm_type), repr(hohm_data))

        if hohm_type not in HOHM_ODD_TYPES:
            hohm_data = hohm_data[16:]

            # What even is character encoding?
            # There might be something telling us what the encoding is but this
            # is sufficient for current purposes.
            if len(hohm_data) > 1 and len(hohm_data) % 2 == 0 and hohm_data[0] == 0:
                hohm_data = hohm_data.decode('iso-8859-1')
            elif len(hohm_data) > 1 and len(hohm_data) % 2 == 0 and hohm_data[-1] == 0:
                hohm_data = hohm_data.decode('utf-16le')
            else:
                hohm_data = hohm_data.decode('iso-8859-1')

        return Hohm(record_length=record_length, type=hohm_type, data=hohm_data)

    def parse_halm(self, data):
        return Halm()

    def parse_haim(self, data):
        return Haim()

    def parse_hilm(self, data):
        return Hilm()

    def parse_hiim(self, data):
        return Hiim()

    def parse_htlm(self, data):
        return Htlm()

    def parse_htim(self, data):
        record_length = data.read_uint()
        sub_blocks = data.read_uint()
        song_id = data.read_uint()
        block_type = data.read_uint()

        # data = self.data.read(record_length - len(data.getvalue()) - 8)
        # print(repr(data))

        return Htim(record_length, sub_blocks, song_id, block_type)

    def parse_hqlm(self, data):
        return Hqlm()

    def parse_hqim(self, data):
        return Hqim()

    def parse_hsts(self, data):
        return Hsts()

    def parse_hplm(self, data):
        return Hplm()

    def parse_hpim(self, data):
        data.skip(4 + 4)
        item_count = data.read_uint()
        return Hpim(item_count)

    def parse_hptm(self, data):
        data.skip(16)
        key = data.read_uint()
        return Hptm(key)

    def parse_hslm(self, data):
        return Hslm()

    def parse_hpsm(self, data):
        return Hpsm()

    def parse_hrlm(self, data):
        return Hrlm()

    def parse_hrpm(self, data):
        return Hrpm()


parser = argparse.ArgumentParser()
parser.add_argument('filename', nargs='?', default='iTunes Library.itl',
                    help='iTunes Library Filename')
args = parser.parse_args()

# So it appears that the .itl format, in modern versions of iTunes, has a header
# block containing some information, one part of which tells us how much of the
# following data is AES/ECB encrypted with a key that's made it around the
# Internet a bit. To get at the actual data you need to decrypt that bit in place
# then decompress (zlib) the bit after the initial header. After that it's a similar
# format to older iTunes library files.

itl = open(args.filename, 'rb').read()
header = itl[:HEADER_LENGTH]

crypt_length = (len(itl) - HEADER_LENGTH) & ~0xf
max_crypt_length = struct.unpack('>I', header[0x5C:0x60])[0]
crypt_length = min(crypt_length, max_crypt_length)

cipher = AES.new(CRYPTO_KEY, AES.MODE_ECB)
decrypted = cipher.decrypt(itl[HEADER_LENGTH:max_crypt_length + HEADER_LENGTH])

itl = decrypted + itl[max_crypt_length + HEADER_LENGTH:]
itl = header + zlib.decompress(itl)

track = {}
tracks = {}
playlist = {}
playlists = {}

# with open("/Users/kaipi/Desktop/parseditl.txt", "wb") as file:
#   file.write(itl)

with open("/Users/kaipi/Desktop/parseditl.txt", "rb") as file:
  itl = file.read()

for record in RecordParser(itl).parse():
    if type(record) is Htim:
        if track:
            tracks[track['song_id']] = track
        track = {'song_id': record.song_id}
    elif type(record) is Hohm:
        if record.type == HohmType.TITLE:
            track['title'] = record.data
        elif record.type == HohmType.ALBUM_TITLE:
            track['album'] = record.data
        elif record.type == HohmType.ARTIST:
            track['artist'] = record.data
        elif record.type == HohmType.LOCAL_PATH:
            track['path'] = record.data
        elif record.type == HohmType.PLAYLIST_TITLE:
            playlist['title'] = record.data
    elif type(record) is Hpim:
        if playlist:
            playlists[playlist['title']] = playlist
        playlist = {'items': []}
    elif type(record) is Hptm:
        playlist['items'].append(record.key)

if track:
    tracks[track['song_id']] = track

if playlist:
    playlists[playlist['title']] = playlist

output = csv.writer(open('playlists.csv', 'w'))

for title, playlist in playlists.items():
    # print(title, playlist)
    # The playlists I was after had titles of the form 'YYYY-M' or 'YYYY-MM'...
    # if len(title) < 5 or title[0] != '2' or title[4] != '-':
    #     continue
    # year, month = title.split('-')
    # ... and I wanted to make them consistently 'YYYY-MM'.
    # title = f'{year}-{int(month):02d}'

    with open(f"/Users/kaipi/Desktop/playlists/{title.replace("- ", " ").replace("\\ ", " ")}.playlist.m3u8", "wb") as playlist_file:
      playlist_file.write(b'\xEF\xBB\xBF')
      for item in (tracks[x] for x in playlist['items']):
          # print(repr(item))

          if item.get('path', None) and item['path'].startswith("file://localhost/C:/Users/Patricio%20Tagle/Music"):
            path = item['path'].replace("file://localhost/C:/Users/Patricio%20Tagle/Music/", "/storage/external_sd/Music/")
            path = unicodedata.normalize("NFD", unquote(path))

            playlist_file.write((path + "\n").encode())
            output.writerow([title, item['title'], item.get('artist', "n/a"), item.get('album', ''), unquote(path)])