package goutils

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// exiftool -a -G1 -time:all FILE
// exiftool -htmlDump FILE
// hexdump -C FILE

// AVI RIFF File Reference: https://msdn.microsoft.com/en-us/library/ms779636.aspx
// Nikon Tags: https://www.sno.phy.queensu.ca/~phil/exiftool/TagNames/Nikon.html#AVITags

type ErrNoOriginalTime struct {
	s string
}

func (err *ErrNoOriginalTime) Error() string {
	if len(err.s) != 0 {
		return fmt.Sprintf("original time not found: %s", err.s)
	} else {
		return fmt.Sprint("original time not found")
	}
}

var zeroTime = time.Time{}

func FileTime(path string) (time.Time, error) {
	created, err := FileOriginalTime(path)

	if err != nil {
		if fi, err := os.Stat(path); err == nil {
			return fi.ModTime(), nil
		}
	}
	return created, err
}

// FileOriginalTime returns the original time for file p.
func FileOriginalTime(p string) (time.Time, error) {
	ext := strings.ToLower(filepath.Ext(p))
	switch ext {
	case ".mov", ".mp4", ".m4v", ".m4a":
		return movOriginalTime(p)
	case ".jpg", ".jpeg", ".arw", ".nef":
		r, err := os.Open(p)
		if err != nil {
			return zeroTime, err
		}
		defer r.Close()
		t, err := ExtractExifDateTime(r)
		if err != nil {
			return guessTimeFromFilename(p)
		}
		return t, nil
	case ".avi":
		// Currently only support *.avi created by Nikon
		return aviOriginalTime(p)
	default:
		return guessTimeFromFilename(p)
	}
}

// func imageOriginalTime(p string) (time.Time, error) {
// 	f, err := os.Open(p)
// 	if err != nil {
// 		return time.Time{}, err
// 	}

// 	x, err := exif.Decode(f)
// 	if err != nil {
// 		return guessTimeFromFilename(p)
// 	}
// 	if t, err := x.DateTime(); err == nil {
// 		return t, err
// 	} else {
// 		return guessTimeFromFilename(p)
// 	}
// }

func movOriginalTime(p string) (originalTime time.Time, err error) {
	ATOM_HEADER_SIZE := 8
	// difference between Unix epoch and QuickTime epoch, in seconds
	EPOCH_ADJUSTER := 2082844800
	// EPOCH_ADJUSTER := 0

	// open file and search for moov item
	in, err := os.Open(p)
	if err != nil {
		return
	}
	defer in.Close()

	atomHeader := make([]byte, ATOM_HEADER_SIZE)
	dword := make([]byte, 4)
	for {
		_, err = in.Read(atomHeader)
		if err != nil {
			return
		}
		if bytes.Compare(atomHeader[4:8], []byte("moov")) == 0 {
			break
		} else {
			atomSize := int64(binary.BigEndian.Uint32(atomHeader[0:4]))
			in.Seek(atomSize-8, 1)
		}
	}

	// found 'moov', look for 'mvhd' and timestamps
	_, err = in.Read(atomHeader)
	if err != nil {
		return
	}
	if bytes.Compare(atomHeader[4:8], []byte("cmov")) == 0 {
		err = &ErrNoOriginalTime{"moov atom is compressed"}
		return
	} else if bytes.Compare(atomHeader[4:8], []byte("mvhd")) != 0 {
		err = &ErrNoOriginalTime{"expected to find 'mvhd' header"}
		return
	} else {
		in.Seek(4, 1)
		if _, err = in.Read(dword); err != nil {
			return
		}
		timestamp := int64(binary.BigEndian.Uint32(dword))
		timestamp -= int64(EPOCH_ADJUSTER)
		if timestamp <= 0 {
			return guessTimeFromFilename(p)
		}
		originalTime = time.Unix(timestamp, 0)

		// if _, err = in.Read(dword); err != nil {
		// 	return nil, err
		// }
		// modificationDate := time.Unix(int64(binary.BigEndian.Uint32(dword[0:4])), 0)

		return
	}
}

func aviOriginalTime(p string) (originalTime time.Time, err error) {
	// open file and search for moov item
	in, err := os.Open(p)
	if err != nil {
		return
	}
	defer in.Close()

	dword := make([]byte, 4)
	if _, err = in.Read(dword); err != nil {
		return
	}

	if bytes.Compare(dword, []byte("RIFF")) != 0 {
		err = &ErrNoOriginalTime{"Invalid AVI file: No RIFF"}
		return
	}
	if _, err = in.Read(dword); err != nil {
		return
	}
	if _, err = in.Read(dword); err != nil {
		return
	}
	if bytes.Compare(dword[:3], []byte("AVI")) != 0 {
		err = &ErrNoOriginalTime{"Invalid AVI file: No AVI"}
		return
	}
	return handleRIFFList(in)
}

func handleRIFFList(in io.ReadSeeker) (originalTime time.Time, err error) {
	dword := make([]byte, 4)
	for {
		if _, err = in.Read(dword); err != nil {
			return
		}
		if bytes.Compare(dword, []byte("LIST")) != 0 {
			err = &ErrNoOriginalTime{"Invalid AVI file: No LIST"}
			return
		}

		if _, err = in.Read(dword); err != nil {
			return
		}
		listSize := int64(binary.LittleEndian.Uint32(dword))
		if _, err = in.Read(dword); err != nil {
			return
		}
		listType := string(dword)

		if listType == "ncdt" {
			// fmt.Println("found it!")
			return handleRIFFChunk(in)
		}
		// fmt.Println(listType, listSize)
		in.Seek(listSize-4, os.SEEK_CUR)
	}
}

func handleRIFFChunk(in io.ReadSeeker) (originalTime time.Time, err error) {
	dword := make([]byte, 4)
	for {
		if _, err = in.Read(dword); err != nil {
			return
		}
		ckID := string(dword)
		if _, err = in.Read(dword); err != nil {
			return
		}
		ckSize := binary.LittleEndian.Uint32(dword)
		if ckID != "nctg" {
			in.Seek(int64(ckSize), os.SEEK_CUR)
			continue
		}

		// process nctg data
		return handleRIFFChunkTags(in)
	}
}

func handleRIFFChunkTags(in io.ReadSeeker) (originalTime time.Time, err error) {
	word := make([]byte, 2)
	for {
		if _, err = in.Read(word); err != nil {
			return
		}
		tagID := binary.LittleEndian.Uint16(word)
		if _, err = in.Read(word); err != nil {
			return
		}
		tagSize := binary.LittleEndian.Uint16(word)
		if tagID != 0x0013 {
			in.Seek(int64(tagSize), os.SEEK_CUR)
			continue
		}

		tagData := make([]byte, tagSize)
		if _, err = in.Read(tagData); err != nil {
			return
		}
		return parseTime(string(tagData))
	}
}

func guessTimeFromFilename(p string) (time.Time, error) {
	// fmt.Printf("guessTimeFromFilename: %s\n", p)
	name := path.Base(p)

	// Try parse time
	var digits bytes.Buffer
	for _, c := range name {
		if c >= '0' && c <= '9' && digits.Len() < 14 {
			digits.WriteRune(c)
		}
	}

	if digits.Len() < 8 {
		return time.Time{}, &ErrNoOriginalTime{}
	}
	s := digits.String()

	layout := "20060102150405"
	if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
		return t, err
	}

	// Try parse date
	layout = "20060102"
	if t, err := time.ParseInLocation(layout, s[:8], time.Local); err == nil {
		return t, err
	}

	// Try timestamp
	digits.Reset()
	// Read a continuous of digits
	started := false
	for _, c := range name {
		if c >= '0' && c <= '9' && digits.Len() < 14 {
			started = true
			digits.WriteRune(c)
		} else {
			if started {
				break
			}
		}
	}

	// timestamp of 1980.1.1 is 315504000000.0 ms
	if digits.Len() < 12 {
		return time.Time{}, &ErrNoOriginalTime{}
	}
	s = digits.String()

	timestamp, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return time.Time{}, &ErrNoOriginalTime{}
	}
	originalTime := time.Unix(int64(timestamp/1000.0), int64(timestamp%1000*1000*1000))
	return originalTime, nil
}

// ExtractExifDateTime extract Exif date time from the reader r
// `exiftool -htmlDump /path/to/file` is very usefull
func ExtractExifDateTime(r io.Reader) (time.Time, error) {
	head := make([]byte, 2)
	n, err := r.Read(head)
	if err != nil {
		return zeroTime, err
	}
	if n < len(head) {
		return zeroTime, errors.New("invalid image file: header too short")
	}

	switch string(head) {
	case "\xFF\xD8":
		return handleJPG(r)
	case "II", "MM":
		s := r.(io.Seeker)
		s.Seek(-2, io.SeekCurrent)
		return parseTIFF(r, 0)
	default:
		// fmt.Fprintf(os.Stderr, "%x\n", head)
		return zeroTime, errors.New("header error")
	}
}

func handleJPG(r io.Reader) (time.Time, error) {

	marker := make([]byte, 2)
	for {
		n, err := r.Read(marker)
		if err != nil {
			return zeroTime, err
		}
		if n < len(marker) {
			return zeroTime, errors.New("invalid image file: header too short")
		}

		// Extract app1 size
		var size uint16
		err = binary.Read(r, binary.BigEndian, &size)
		if err != nil {
			return zeroTime, err
		}

		switch string(marker) {
		case "\xFF\xE1":
			// Found App1
			app1Data := make([]byte, size-2)
			n, err = io.ReadFull(r, app1Data)
			if err != nil {
				return zeroTime, errors.New("exif: no enough app1 data")
			}
			app1Reader := bytes.NewReader(app1Data)

			// read/check for exif special mark
			const EXIF_MARKER = "Exif\x00\x00"
			exif := make([]byte, len(EXIF_MARKER))
			n, err = io.ReadFull(app1Reader, exif)
			if err != nil {
				return zeroTime, errors.New("exif: failed to find exif intro marker")
			}

			if !bytes.Equal(exif, []byte(EXIF_MARKER)) {
				return zeroTime, errors.New("exif: failed to find exif intro marker")
			}

			return parseTIFF(app1Reader, int64(len(EXIF_MARKER)))
		default:
			// skip this APP data
			s := r.(io.Seeker)
			s.Seek(int64(size)-2, os.SEEK_CUR)
		}
	}
}

func parseTIFF(app1Reader io.Reader, headerOffset int64) (time.Time, error) {

	tiff := make([]byte, 4)
	_, err := io.ReadFull(app1Reader, tiff)
	if err != nil {
		return zeroTime, errors.New("exif: failed to find tiff")
	}
	isLittleEndian := false
	switch string(tiff) {
	case "II*\x00":
		// TIFF - Little endian (Intel)
		isLittleEndian = true
	case "MM\x00*":
		// TIFF - Big endian (Motorola)
	default:
		// Not TIFF, assume JPEG
		return zeroTime, errors.New("is not tiff")
	}

	var endian binary.ByteOrder
	if isLittleEndian {
		endian = binary.LittleEndian
	} else {
		endian = binary.BigEndian
	}

	var offset int32

	for {
		err = binary.Read(app1Reader, endian, &offset)
		if err != nil {
			return zeroTime, errors.New("exif: no next IFD offset")
		}
		if offset == 0 {
			return zeroTime, errors.New("no time found")
		}

		// fmt.Printf("offset: %04x\n", offset)

		s := app1Reader.(io.Seeker)
		s.Seek(headerOffset, io.SeekStart)
		s.Seek(int64(offset), io.SeekCurrent)

		return parseDirEntry(app1Reader, endian, headerOffset)
	}

}

func parseDirEntry(app1Reader io.Reader, endian binary.ByteOrder, headerOffset int64) (time.Time, error) {
	var dirEntryCount int16
	binary.Read(app1Reader, endian, &dirEntryCount)
	// fmt.Printf("dirEntryCount: %d\n", dirEntryCount)
	s := app1Reader.(io.Seeker)

	for i := 0; i < int(dirEntryCount); i++ {
		var tag, dtype uint16
		var length, valueOffset uint32
		binary.Read(app1Reader, endian, &tag)
		binary.Read(app1Reader, endian, &dtype)
		binary.Read(app1Reader, endian, &length)
		binary.Read(app1Reader, endian, &valueOffset)
		// fmt.Printf("tag: %04x valueOffset: %04x\n", tag, valueOffset)
		switch tag {
		case 0x0132, 0x9003:
			s.Seek(headerOffset, io.SeekStart)
			s.Seek(int64(valueOffset), io.SeekCurrent)
			timeData := make([]byte, length)
			_, err := io.ReadFull(app1Reader, timeData)
			if err != nil {
				return zeroTime, err
			}
			return parseTime(string(timeData))
		case 0x8769:
			// EXIF offset
			s.Seek(headerOffset, io.SeekStart)
			s.Seek(int64(valueOffset), io.SeekCurrent)
			return parseDirEntry(app1Reader, endian, headerOffset)
		}
	}

	return zeroTime, errors.New("no time found")
}

func parseTime(name string) (time.Time, error) {
	// Try parse time
	var digits bytes.Buffer
	for _, c := range name {
		if c >= '0' && c <= '9' && digits.Len() < 14 {
			digits.WriteRune(c)
		}
	}

	if digits.Len() < 8 {
		return time.Time{}, errors.New("invalid time string")
	}
	s := digits.String()

	layout := "20060102150405"
	t, err := time.ParseInLocation(layout, s, time.Local)
	if err != nil {
		return t, err
	}
	return t, nil
}
