package main

type radixTreeNode struct {
	depth  int
	parent *radixTreeNode
	node0  *radixTreeNode // 0 を入れる左のノード
	node1  *radixTreeNode // 1 を入れる右のノード
	data   ipRouteEntry
	value  int
}

// ツリー ( ルーティングテーブル ) にルーティング情報を登録する
func (node *radixTreeNode) radixTreeAdd(prefixIpAddr uint32, prefixLen int, entryData ipRouteEntry) {
	// ルートノードからたどる
	current := node
	// 枝をたどる
	for i := 1; i <= prefixLen; i++ {
		if prefixIpAddr>>(32-i)&0x01 == 1 { // 上から i ビットめが 1 なら
			if current.node1 == nil {
				current.node1 = &radixTreeNode{
					parent: current,
					depth:  i,
					value:  0,
				}
			}
			current = current.node1
		} else { // 上から i ビットめが 0 なら
			// たどる先の枝がなかったら作る
			if current.node0 == nil {
				current.node0 = &radixTreeNode{
					parent: current,
					depth:  i,
					value:  0,
				}
			}
			current = current.node0
		}
	}
	// 最後にデータをセット
	current.data = entryData
}

// ルーティングテーブルを検索する
func (node *radixTreeNode) radixTreeSearch(prefixIpAddr uint32) ipRouteEntry {
	current := node
	var result ipRouteEntry
	for i := 1; i <= 32; i++ {
		if current.data != (ipRouteEntry{}) {
			result = current.data
		}
		if (prefixIpAddr>>(32-i))&0x01 == 1 { // 上から i ビットめが 1 だったら
			if current.node1 == nil {
				return result
			}
			current = current.node1
		} else { // 上から i ビットめが 0 だったら
			if current.node0 == nil {
				return result
			}
			current = current.node0
		}
	}
	return result
}
