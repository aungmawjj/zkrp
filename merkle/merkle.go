/*
 * Copyright (C) 2019 Daniel Reijsbergen
 *
 * based on https://github.com/cbergoon/merkletree/blob/master/merkle_tree.go by Cameron Bergoon
 */

package merkle

import (
	//    "fmt"
	//    "math"
	"math/big"
	//    "math/rand"
	"encoding/json"

	"github.com/aungmawjj/zkrp/bulletproofs"
	"github.com/aungmawjj/zkrp/crypto/p256"
	"github.com/aungmawjj/zkrp/util"
)

type Path struct {
	Core []*Node
	Edge []*Node
}

type Node struct {
	Parent *Node `json:"-"`
	Left   *Node `json:"-"`
	Right  *Node `json:"-"`
	IsLeaf bool
	Index  int
	Height int
	L      int
	C1     []byte
	C2     []byte
	Pi     []byte
}

func buildLeaf(reading int, seed *big.Int, d int64) *Node {
	p, _ := bulletproofs.SetupGeneric(0, d)
	proof, _ := bulletproofs.ProveGeneric(big.NewInt(int64(reading)), p, seed)
	nodeC1, _ := json.Marshal(proof.P1.V)
	nodeC2, _ := json.Marshal(proof.P2.V)
	nodePi, _ := json.Marshal(proof)
	n := &Node{
		C1:     nodeC1,
		C2:     nodeC2,
		Pi:     nodePi,
		L:      1,
		IsLeaf: true,
		Height: 0,
	}
	return n
}

func buildIntermediate(ns []*Node, vs []int, ls []int, rs []*big.Int, d int64) *Node {
	var nodes []*Node
	var values []int
	var sizes []int
	var seeds []*big.Int
	var sumV int
	var newL int
	var sumR *big.Int
	for i := 0; i < len(ns); i += 2 {
		var leftNode, rightNode *Node
		if i+1 == len(ns) {
			nodes = append(nodes, ns[i])
			values = append(values, vs[i])
			sizes = append(sizes, ls[i])
			seeds = append(seeds, rs[i])
			if len(ns) == 2 {
				return ns[i]
			}
		} else {
			sumV = vs[i] + vs[i+1]
			sumR = new(big.Int).Add(rs[i], rs[i+1])
			leftNode = ns[i]
			rightNode = ns[i+1]
			newL = ls[i] + ls[i+1]
			height := leftNode.Height + 1
			p, _ := bulletproofs.SetupGeneric(0, d*int64(newL))
			proof, _ := bulletproofs.ProveGeneric(big.NewInt(int64(sumV)), p, sumR)
			nodeC1, _ := json.Marshal(proof.P1.V)
			nodeC2, _ := json.Marshal(proof.P2.V)
			nodePi, _ := json.Marshal(proof)
			n := &Node{
				Left:   leftNode,
				Right:  rightNode,
				C1:     nodeC1,
				C2:     nodeC2,
				Pi:     nodePi,
				L:      newL,
				IsLeaf: false,
				Height: height,
			}
			nodes = append(nodes, n)
			values = append(values, sumV)
			sizes = append(sizes, newL)
			seeds = append(seeds, sumR)
			leftNode.Parent = n
			rightNode.Parent = n
			if len(ns) == 2 {
				return n
			}
		}
	}
	return buildIntermediate(nodes, values, sizes, seeds, d)
}

func verifyCommitmentSum(root, na, nb *Node, delta int64) bool {
	var C1root, C2root, C1a, C1b, C2a, C2b, C1sum, C2sum *p256.P256
	// C1 in parent should equal xa + xb - root.l * delta + max
	// C1 in child a should equal xa - na.l * delta + max
	// C1 in child b should equal xb - nb.l * delta + max
	//  need dummies to compare
	p, _ := bulletproofs.SetupGeneric(0, delta)
	dummy := int64(10)
	sumAdj, _ := util.CommitG1(big.NewInt(int64(dummy-bulletproofs.MAX_RANGE_END)), big.NewInt(int64(dummy)), p.BP2.H)
	rootAdj, _ := util.CommitG1(big.NewInt(int64(dummy)), big.NewInt(int64(dummy)), p.BP2.H)
	_ = json.Unmarshal(root.C1, &C1root)
	_ = json.Unmarshal(na.C1, &C1a)
	_ = json.Unmarshal(nb.C1, &C1b)
	C1sum = new(p256.P256).Add(C1a, C1b)
	adjC1sum := new(p256.P256).Add(C1sum, sumAdj)
	adjC1root := new(p256.P256).Add(C1root, rootAdj)

	// C2 in parent should equal sum of commitments in children
	_ = json.Unmarshal(root.C2, &C2root)
	_ = json.Unmarshal(na.C2, &C2a)
	_ = json.Unmarshal(nb.C2, &C2b)
	C2sum = new(p256.P256).Add(C2a, C2b)

	return C2sum.Equals(C2root) && adjC1sum.Equals(adjC1root)
}

//func VerifyTree(n *Node, gamma, delta int64) (bool) {
//    if(n.IsLeaf) {
//        return true
//    }
//    return verifyCommitmentSum(n, n.Left, n.Right) && VerifyTree(n.Left) && VerifyTree(n.Right)
//}

func (p *Path) VerifyStructure(delta int64) bool {
	for i := 0; i < len(p.Edge); i++ {
		if !verifyCommitmentSum(p.Core[i+1], p.Core[i], p.Edge[i], delta) {
			return false
		}
	}
	return true
}

func (p *Path) VerifyProofs() bool {

	var (
		proof   bulletproofs.ProofBPRP
		commit1 *p256.P256
		commit2 *p256.P256
	)

	for i := 0; i < len(p.Core); i++ {
		_ = json.Unmarshal(p.Core[i].Pi, &proof)
		_ = json.Unmarshal(p.Core[i].C1, &commit1)
		_ = json.Unmarshal(p.Core[i].C2, &commit2)

		ok1 := proof.P1.V.Equals(commit1)
		ok2 := proof.P2.V.Equals(commit2)
		ok3, _ := proof.Verify()

		//fmt.Println(ok1, ok2, ok3)

		if !(ok1 && ok2 && ok3) {
			return false
		}
	}
	for i := 0; i < len(p.Edge); i++ {
		_ = json.Unmarshal(p.Edge[i].Pi, &proof)
		_ = json.Unmarshal(p.Edge[i].C1, &commit1)
		_ = json.Unmarshal(p.Edge[i].C2, &commit2)

		ok1 := proof.P1.V.Equals(commit1)
		ok2 := proof.P2.V.Equals(commit2)
		ok3, _ := proof.Verify()

		//fmt.Println(ok1, ok2, ok3)

		if !(ok1 && ok2 && ok3) {
			return false
		}
	}
	return true
}

func (n *Node) CopyNode() *Node {
	// deep copy byte arrays
	nodeC1 := make([]byte, len(n.C1))
	nodeC2 := make([]byte, len(n.C2))
	nodePi := make([]byte, len(n.Pi))
	copy(nodeC1, n.C1)
	copy(nodeC2, n.C2)
	copy(nodePi, n.Pi)
	result := &Node{
		C1: nodeC1,
		C2: nodeC2,
		Pi: nodePi,
		L:  n.L,
	}
	return result
}

func (root *Node) MerklePath(leaf *Node) *Path {
	cNode := leaf
	core := make([]*Node, 1)
	core[0] = cNode.CopyNode()
	core[0].IsLeaf = true
	edge := make([]*Node, 0)
	for cNode != root {
		pNode := cNode.Parent
		core = append(core, pNode.CopyNode())
		if cNode == pNode.Left {
			edge = append(edge, pNode.Right.CopyNode())
			core[len(core)-1].Left = core[len(core)-2]
			core[len(core)-1].Right = edge[len(edge)-1]
		} else if cNode == pNode.Right { // sanity check
			edge = append(edge, pNode.Left.CopyNode())
			core[len(core)-1].Right = core[len(core)-2]
			core[len(core)-1].Left = edge[len(edge)-1]
		}
		core[len(core)-2].Parent = core[len(core)-1]
		core[len(core)-1].IsLeaf = false
		edge[len(edge)-1].IsLeaf = true
		cNode = pNode
		//fmt.Println("h", cNode.Height)
	}

	//valid := VerifyTree(cNode)
	//fmt.Println("path valid:",valid)

	// create path
	path := &Path{
		Core: core,
		Edge: edge,
	}

	return path
}

func (n *Node) GetNumLeaves() int {
	if n.IsLeaf {
		return 1
	}
	return n.Left.GetNumLeaves() + n.Right.GetNumLeaves()
}

func (n *Node) GetLeaf(index int) *Node {
	var (
		node1 *Node
		node2 *Node
	)
	if n.IsLeaf {
		if n.Index == index {
			return n
		}
		return nil
	}
	node1 = n.Left.GetLeaf(index)
	node2 = n.Right.GetLeaf(index)
	if node1 != nil {
		return node1
	}
	if node2 != nil {
		return node2
	}
	return nil
}

// return the root node
func (n *Node) BuildTree(vs map[int]int, rs map[int]*big.Int, d int64) *Node {
	// initialize the leaves
	leaves := make([]*Node, len(vs))
	values := make([]int, len(vs))
	sizes := make([]int, len(vs))
	seeds := make([]*big.Int, len(vs))
	for k := range vs {
		values[k] = vs[k]
		seeds[k] = rs[k]
		n := buildLeaf(vs[k], rs[k], d)
		leaves[k] = n
		sizes[k] = 1
		leaves[k].Index = k
	}
	root := buildIntermediate(leaves, values, sizes, seeds, d)
	// verify full tree
	//    valid := VerifyTree(root)
	//    fmt.Println("full tree valid:",valid)
	return root
}
