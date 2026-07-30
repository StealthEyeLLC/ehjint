// Package cidata builds and validates the deterministic FAT16 NoCloud seed
// used by EHJINT. It has no cloud-localds, xorriso, genisoimage, or mtools
// runtime dependency.
package cidata

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"unicode/utf16"
)

const (
	sectorSize        = 512
	sectorsPerCluster = 1
	reservedSectors   = 1
	fatCopies         = 2
	rootEntries       = 512
	rootSectors       = rootEntries * 32 / sectorSize
	minimumClusters   = 4085
	maximumClusters   = 65524
	mediaDescriptor   = 0xf8
	fatDate1980       = 0x0021
)

var volumeLabel = [11]byte{'C', 'I', 'D', 'A', 'T', 'A', ' ', ' ', ' ', ' ', ' '}

// Metadata identifies a validated CIDATA image.
type Metadata struct {
	VolumeID     uint32
	TotalSectors uint16
	FATSectors   uint16
	DataClusters uint16
	SHA256       string
	Files        map[string][]byte
}

type sourceFile struct {
	longName  string
	shortName [11]byte
	data      []byte
	start     uint16
	clusters  uint16
}

// BuildNoCloud creates one FAT16 CIDATA image containing exact meta-data and
// user-data long filenames.
func BuildNoCloud(metaData, userData []byte) ([]byte, Metadata, error) {
	if len(metaData) == 0 || len(userData) == 0 {
		return nil, Metadata{}, fmt.Errorf("NoCloud meta-data and user-data must both be non-empty")
	}
	files := []sourceFile{
		{longName: "meta-data", shortName: shortAlias("META-D~1"), data: append([]byte(nil), metaData...)},
		{longName: "user-data", shortName: shortAlias("USER-D~1"), data: append([]byte(nil), userData...)},
	}
	sort.Slice(files, func(i, j int) bool { return files[i].longName < files[j].longName })
	usedClusters := 0
	for index := range files {
		clusters := (len(files[index].data) + sectorSize - 1) / sectorSize
		if clusters == 0 || clusters > maximumClusters {
			return nil, Metadata{}, fmt.Errorf("NoCloud file %q exceeds FAT16 bounds", files[index].longName)
		}
		files[index].clusters = uint16(clusters)
		usedClusters += clusters
	}
	dataClusters := usedClusters + 16
	if dataClusters < minimumClusters {
		dataClusters = minimumClusters
	}
	if dataClusters > maximumClusters {
		return nil, Metadata{}, fmt.Errorf("NoCloud seed exceeds FAT16 cluster limit")
	}
	fatSectors := ((dataClusters+2)*2 + sectorSize - 1) / sectorSize
	totalSectors := reservedSectors + fatCopies*fatSectors + rootSectors + dataClusters
	if totalSectors > 0xffff {
		return nil, Metadata{}, fmt.Errorf("NoCloud seed exceeds canonical FAT16 sector limit")
	}
	image := make([]byte, totalSectors*sectorSize)
	volumeID := deriveVolumeID(files)
	writeBootSector(image[:sectorSize], uint16(totalSectors), uint16(fatSectors), volumeID)

	fatOffset := reservedSectors * sectorSize
	fatBytes := fatSectors * sectorSize
	fat := image[fatOffset : fatOffset+fatBytes]
	binary.LittleEndian.PutUint16(fat[0:2], 0xff00|mediaDescriptor)
	binary.LittleEndian.PutUint16(fat[2:4], 0xffff)
	nextCluster := uint16(2)
	for index := range files {
		files[index].start = nextCluster
		for offset := uint16(0); offset < files[index].clusters; offset++ {
			cluster := nextCluster + offset
			value := uint16(0xffff)
			if offset+1 < files[index].clusters {
				value = cluster + 1
			}
			binary.LittleEndian.PutUint16(fat[int(cluster)*2:int(cluster)*2+2], value)
		}
		nextCluster += files[index].clusters
	}
	copy(image[fatOffset+fatBytes:fatOffset+2*fatBytes], fat)

	rootOffset := (reservedSectors + fatCopies*fatSectors) * sectorSize
	root := image[rootOffset : rootOffset+rootSectors*sectorSize]
	copy(root[0:11], volumeLabel[:])
	root[11] = 0x08
	entry := 1
	for _, file := range files {
		longEntry, err := longNameEntry(file.longName, file.shortName)
		if err != nil {
			return nil, Metadata{}, err
		}
		copy(root[entry*32:(entry+1)*32], longEntry[:])
		entry++
		writeShortEntry(root[entry*32:(entry+1)*32], file)
		entry++
	}

	dataOffset := rootOffset + rootSectors*sectorSize
	for _, file := range files {
		start := dataOffset + (int(file.start)-2)*sectorSize
		copy(image[start:start+len(file.data)], file.data)
	}
	metadata, err := Inspect(image)
	if err != nil {
		return nil, Metadata{}, fmt.Errorf("inspect constructed CIDATA image: %w", err)
	}
	return image, metadata, nil
}

// Inspect validates the complete canonical FAT16 image and extracts its files.
func Inspect(image []byte) (Metadata, error) {
	if len(image) < sectorSize || len(image)%sectorSize != 0 {
		return Metadata{}, fmt.Errorf("CIDATA image is not sector aligned")
	}
	boot := image[:sectorSize]
	if boot[510] != 0x55 || boot[511] != 0xaa || binary.LittleEndian.Uint16(boot[11:13]) != sectorSize ||
		boot[13] != sectorsPerCluster || binary.LittleEndian.Uint16(boot[14:16]) != reservedSectors ||
		boot[16] != fatCopies || binary.LittleEndian.Uint16(boot[17:19]) != rootEntries || boot[21] != mediaDescriptor ||
		string(boot[43:54]) != string(volumeLabel[:]) || string(boot[54:62]) != "FAT16   " {
		return Metadata{}, fmt.Errorf("invalid canonical CIDATA FAT16 boot sector")
	}
	totalSectors := int(binary.LittleEndian.Uint16(boot[19:21]))
	fatSectors := int(binary.LittleEndian.Uint16(boot[22:24]))
	if totalSectors*sectorSize != len(image) || fatSectors <= 0 {
		return Metadata{}, fmt.Errorf("CIDATA geometry does not match image size")
	}
	dataClusters := totalSectors - reservedSectors - fatCopies*fatSectors - rootSectors
	if dataClusters < minimumClusters || dataClusters > maximumClusters {
		return Metadata{}, fmt.Errorf("CIDATA cluster count is outside FAT16 range")
	}
	fatOffset := reservedSectors * sectorSize
	fatBytes := fatSectors * sectorSize
	if fatOffset+2*fatBytes > len(image) {
		return Metadata{}, fmt.Errorf("CIDATA FAT tables exceed image")
	}
	firstFAT := image[fatOffset : fatOffset+fatBytes]
	secondFAT := image[fatOffset+fatBytes : fatOffset+2*fatBytes]
	if !bytes.Equal(firstFAT, secondFAT) || binary.LittleEndian.Uint16(firstFAT[0:2]) != 0xff00|mediaDescriptor || binary.LittleEndian.Uint16(firstFAT[2:4]) != 0xffff {
		return Metadata{}, fmt.Errorf("CIDATA FAT copies or reserved entries are invalid")
	}
	rootOffset := (reservedSectors + fatCopies*fatSectors) * sectorSize
	root := image[rootOffset : rootOffset+rootSectors*sectorSize]
	dataOffset := rootOffset + rootSectors*sectorSize
	files := make(map[string][]byte)
	var pendingName string
	var pendingChecksum byte
	volumeSeen := false
	for entry := 0; entry < rootEntries; entry++ {
		record := root[entry*32 : (entry+1)*32]
		if record[0] == 0x00 {
			break
		}
		if record[0] == 0xe5 {
			return Metadata{}, fmt.Errorf("CIDATA contains deleted root entries")
		}
		attribute := record[11]
		if attribute == 0x0f {
			name, checksum, err := parseLongEntry(record)
			if err != nil {
				return Metadata{}, err
			}
			if pendingName != "" {
				return Metadata{}, fmt.Errorf("CIDATA contains multi-entry or orphan long filename")
			}
			pendingName, pendingChecksum = name, checksum
			continue
		}
		if attribute == 0x08 {
			if volumeSeen || string(record[0:11]) != string(volumeLabel[:]) || pendingName != "" {
				return Metadata{}, fmt.Errorf("invalid CIDATA volume-label entry")
			}
			volumeSeen = true
			continue
		}
		if attribute != 0x20 || pendingName == "" || pendingChecksum != shortNameChecksum(record[0:11]) {
			return Metadata{}, fmt.Errorf("CIDATA file entry lacks a valid long filename")
		}
		if pendingName != "meta-data" && pendingName != "user-data" {
			return Metadata{}, fmt.Errorf("unexpected CIDATA file %q", pendingName)
		}
		if _, exists := files[pendingName]; exists {
			return Metadata{}, fmt.Errorf("duplicate CIDATA file %q", pendingName)
		}
		start := binary.LittleEndian.Uint16(record[26:28])
		size := binary.LittleEndian.Uint32(record[28:32])
		data, err := readChain(image, firstFAT, dataOffset, dataClusters, start, size)
		if err != nil {
			return Metadata{}, fmt.Errorf("read CIDATA file %q: %w", pendingName, err)
		}
		files[pendingName] = data
		pendingName = ""
	}
	if pendingName != "" || !volumeSeen || len(files) != 2 || files["meta-data"] == nil || files["user-data"] == nil {
		return Metadata{}, fmt.Errorf("CIDATA root directory is incomplete")
	}
	digest := sha256.Sum256(image)
	return Metadata{
		VolumeID: binary.LittleEndian.Uint32(boot[39:43]), TotalSectors: uint16(totalSectors),
		FATSectors: uint16(fatSectors), DataClusters: uint16(dataClusters),
		SHA256: hex.EncodeToString(digest[:]), Files: files,
	}, nil
}

func writeBootSector(boot []byte, totalSectors, fatSectors uint16, volumeID uint32) {
	copy(boot[0:3], []byte{0xeb, 0x3c, 0x90})
	copy(boot[3:11], "EHJINT  ")
	binary.LittleEndian.PutUint16(boot[11:13], sectorSize)
	boot[13] = sectorsPerCluster
	binary.LittleEndian.PutUint16(boot[14:16], reservedSectors)
	boot[16] = fatCopies
	binary.LittleEndian.PutUint16(boot[17:19], rootEntries)
	binary.LittleEndian.PutUint16(boot[19:21], totalSectors)
	boot[21] = mediaDescriptor
	binary.LittleEndian.PutUint16(boot[22:24], fatSectors)
	binary.LittleEndian.PutUint16(boot[24:26], 32)
	binary.LittleEndian.PutUint16(boot[26:28], 64)
	boot[36] = 0x80
	boot[38] = 0x29
	binary.LittleEndian.PutUint32(boot[39:43], volumeID)
	copy(boot[43:54], volumeLabel[:])
	copy(boot[54:62], "FAT16   ")
	boot[510], boot[511] = 0x55, 0xaa
}

func deriveVolumeID(files []sourceFile) uint32 {
	hash := sha256.New()
	for _, file := range files {
		hash.Write([]byte(file.longName))
		hash.Write([]byte{0})
		var length [8]byte
		binary.LittleEndian.PutUint64(length[:], uint64(len(file.data)))
		hash.Write(length[:])
		hash.Write(file.data)
	}
	return binary.LittleEndian.Uint32(hash.Sum(nil)[:4])
}

func shortAlias(base string) [11]byte {
	var result [11]byte
	for index := range result {
		result[index] = ' '
	}
	copy(result[:8], base)
	return result
}

func longNameEntry(name string, short [11]byte) ([32]byte, error) {
	var entry [32]byte
	units := utf16.Encode([]rune(name))
	if len(units) == 0 || len(units) > 13 {
		return entry, fmt.Errorf("CIDATA filename %q is outside one-entry VFAT bounds", name)
	}
	units = append(units, 0)
	for len(units) < 13 {
		units = append(units, 0xffff)
	}
	entry[0] = 0x41
	entry[11] = 0x0f
	entry[12] = 0
	entry[13] = shortNameChecksum(short[:])
	positions := []int{1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30}
	for index, position := range positions {
		binary.LittleEndian.PutUint16(entry[position:position+2], units[index])
	}
	return entry, nil
}

func parseLongEntry(entry []byte) (string, byte, error) {
	if len(entry) != 32 || entry[0] != 0x41 || entry[11] != 0x0f || entry[12] != 0 || binary.LittleEndian.Uint16(entry[26:28]) != 0 {
		return "", 0, fmt.Errorf("unsupported CIDATA VFAT long-name entry")
	}
	positions := []int{1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30}
	var units []uint16
	terminated := false
	for _, position := range positions {
		unit := binary.LittleEndian.Uint16(entry[position : position+2])
		if unit == 0 {
			terminated = true
			continue
		}
		if unit == 0xffff {
			if !terminated {
				return "", 0, fmt.Errorf("CIDATA VFAT padding precedes terminator")
			}
			continue
		}
		if terminated {
			return "", 0, fmt.Errorf("CIDATA VFAT data follows terminator")
		}
		units = append(units, unit)
	}
	name := string(utf16.Decode(units))
	if name == "" {
		return "", 0, fmt.Errorf("empty CIDATA long filename")
	}
	return name, entry[13], nil
}

func writeShortEntry(entry []byte, file sourceFile) {
	copy(entry[0:11], file.shortName[:])
	entry[11] = 0x20
	binary.LittleEndian.PutUint16(entry[14:16], 0)
	binary.LittleEndian.PutUint16(entry[16:18], fatDate1980)
	binary.LittleEndian.PutUint16(entry[18:20], fatDate1980)
	binary.LittleEndian.PutUint16(entry[22:24], 0)
	binary.LittleEndian.PutUint16(entry[24:26], fatDate1980)
	binary.LittleEndian.PutUint16(entry[26:28], file.start)
	binary.LittleEndian.PutUint32(entry[28:32], uint32(len(file.data)))
}

func shortNameChecksum(short []byte) byte {
	var sum byte
	for _, value := range short {
		sum = ((sum & 1) << 7) + (sum >> 1) + value
	}
	return sum
}

func readChain(image, fat []byte, dataOffset, dataClusters int, start uint16, size uint32) ([]byte, error) {
	if start < 2 || int(start)-2 >= dataClusters || size == 0 {
		return nil, fmt.Errorf("invalid FAT16 start cluster or size")
	}
	result := make([]byte, 0, int(size))
	visited := make(map[uint16]bool)
	cluster := start
	for {
		if cluster < 2 || int(cluster)-2 >= dataClusters || visited[cluster] || int(cluster)*2+2 > len(fat) {
			return nil, fmt.Errorf("invalid or cyclic FAT16 cluster chain")
		}
		visited[cluster] = true
		offset := dataOffset + (int(cluster)-2)*sectorSize
		if offset+sectorSize > len(image) {
			return nil, fmt.Errorf("FAT16 cluster exceeds image")
		}
		remaining := int(size) - len(result)
		count := sectorSize
		if remaining < count {
			count = remaining
		}
		result = append(result, image[offset:offset+count]...)
		next := binary.LittleEndian.Uint16(fat[int(cluster)*2 : int(cluster)*2+2])
		if len(result) == int(size) {
			if next < 0xfff8 {
				return nil, fmt.Errorf("FAT16 chain continues beyond declared size")
			}
			break
		}
		if next >= 0xfff8 || next == 0 {
			return nil, fmt.Errorf("FAT16 chain ended before declared size")
		}
		cluster = next
	}
	return result, nil
}
