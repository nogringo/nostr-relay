package mmm

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/PowerDNS/lmdb-go/lmdb"
)

func (b *MultiMmapManager) gatherFreeRanges(txn *lmdb.Txn) (positions, error) {
	cursor, err := txn.OpenCursor(b.indexId)
	if err != nil {
		return nil, fmt.Errorf("failed to open cursor on indexId: %w", err)
	}
	defer cursor.Close()

	usedPositions := make(positions, 0, 256)
	for key, val, err := cursor.Get(nil, nil, lmdb.First); err == nil; key, val, err = cursor.Get(key, val, lmdb.Next) {
		pos := positionFromBytes(val[0:12])
		usedPositions = append(usedPositions, pos)
	}

	// sort used positions by start
	slices.SortFunc(usedPositions, func(a, b position) int { return cmp.Compare(a.start, b.start) })

	// if there is free space at the end this will simulate it
	usedPositions = append(usedPositions, position{start: b.mmapfEnd, size: 0})

	// calculate free ranges as gaps between used positions
	freeRanges := make(positions, 0, len(usedPositions)/2)
	var currentStart uint64 = 0
	for _, used := range usedPositions {
		if used.start > currentStart {
			// gap from currentStart to pos.start
			freeSize := used.start - currentStart
			if freeSize > 0 {
				freeRanges = append(freeRanges, position{
					start: currentStart,
					size:  uint32(freeSize),
				})
			}
		}
		currentStart = used.start + uint64(used.size)
	}

	return freeRanges, nil
}

func (b *MultiMmapManager) mergeNewFreeRange(newFreeRange position) {
	// use binary search to find the insertion point for the new pos
	idx, exists := slices.BinarySearchFunc(b.freeRanges, newFreeRange.start, func(item position, target uint64) int {
		return cmp.Compare(item.start, target)
	})

	if exists {
		panic(fmt.Errorf("can't add free range that already exists: %s", newFreeRange))
	}

	deleteStart := -1
	deleting := 0

	// check the range immediately before
	if idx > 0 {
		before := b.freeRanges[idx-1]
		if before.start+uint64(before.size) == newFreeRange.start {
			deleteStart = idx - 1
			deleting++
			newFreeRange.start = before.start
			newFreeRange.size = before.size + newFreeRange.size
		}
	}

	// check the range immediately after
	if idx < len(b.freeRanges) {
		after := b.freeRanges[idx]
		if newFreeRange.start+uint64(newFreeRange.size) == after.start {
			if deleteStart == -1 {
				deleteStart = idx
			}
			deleting++

			newFreeRange.size = newFreeRange.size + after.size
		}
	}

	switch deleting {
	case 0:
		// if we are not deleting anything we must insert the new free range
		b.freeRanges = slices.Insert(b.freeRanges, idx, newFreeRange)
	case 1:
		// if we're deleting a single range, don't delete it, modify it in-place instead.
		b.freeRanges[deleteStart] = newFreeRange
	case 2:
		// now if we're deleting two ranges, delete just one instead and modify the other in place
		b.freeRanges[deleteStart] = newFreeRange
		b.freeRanges = slices.Delete(b.freeRanges, deleteStart+1, deleteStart+1+1)
	}
}
