package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/ing-bank/zkrp/bulletproofs"
	"github.com/ing-bank/zkrp/crypto/p256"
	"github.com/ing-bank/zkrp/merkle"
	"github.com/ing-bank/zkrp/util"
)

type System struct {
	users   map[int]*User
	company Company
}

type User struct {
	gamma    int64
	delta    int64
	nUsers   int
	idx      int
	reading  int
	r        *big.Int
	path     *merkle.Path
	sumProof []byte
}

type UserJSON struct {
	Gamma    int64
	Delta    int64
	NUsers   int
	Idx      int
	Reading  int
	R        *big.Int
	Path     *merkle.Path
	SumProof []byte
}

type Company struct {
	gamma    int64
	delta    int64
	nUsers   int
	readings map[int]int
	sum      int
	rs       map[int]*big.Int
	treeRoot *merkle.Node
	sumProof []byte
}

func (s *System) drawReadings(maxN int) {
	for i := 0; i < s.company.nUsers; i++ {
		s.users[i].reading = rand.Intn(maxN)
		fmt.Println(s.users[i].reading)
	}
}

func (s *System) shareReadings() {
	s.company.readings = make(map[int]int)
	for i := 0; i < s.company.nUsers; i++ {
		s.users[i].shareReading(&s.company)
	}
}

func (u *User) shareReading(c *Company) {
	c.readings[u.idx] = u.reading
}

func (c *Company) processReadings() {
	c.sum = 0
	c.treeRoot = new(merkle.Node).BuildTree(c.readings, c.rs, c.delta)
	sumR := big.NewInt(int64(0)) // big.NewInt(int64(c.treeRoot.GetNumLeaves() - c.nUsers)) // because all dummies get r = 1
	for i := 0; i < c.nUsers; i++ {
		c.sum = c.sum + c.readings[i]
		sumR = new(big.Int).Add(sumR, c.rs[i])
	}
	fmt.Println("sum:", c.sum)
	psum, _ := bulletproofs.SetupGeneric(c.gamma, c.delta*int64(c.nUsers))
	proof, _ := bulletproofs.ProveGeneric(big.NewInt(int64(c.sum)), psum, sumR)
	c.sumProof, _ = json.Marshal(proof)
}

func (s *System) shareProofData() {
	node := s.company.treeRoot.GetLeaf(0)
	path := s.company.treeRoot.MerklePath(node)
	s.users[0].path = path
	s.users[0].sumProof = s.company.sumProof
	// for i := 0; i < s.company.nUsers; i++ {
	// 	node := s.company.treeRoot.GetLeaf(i)
	// 	path := s.company.treeRoot.MerklePath(node)
	// 	s.users[i].path = path
	// 	s.users[i].sumProof = s.company.sumProof
	// }
}

func (u *User) checkCommitment() {
	var (
		commit1 *p256.P256
		commit2 *p256.P256
	)

	params, _ := bulletproofs.SetupGeneric(0, u.delta)
	V1, _ := util.CommitG1(big.NewInt(int64(u.reading)-u.delta+bulletproofs.MAX_RANGE_END), u.r, params.BP1.H)
	V2, _ := util.CommitG1(big.NewInt(int64(u.reading)), u.r, params.BP2.H)
	_ = json.Unmarshal(u.path.Core[0].C1, &commit1)
	_ = json.Unmarshal(u.path.Core[0].C2, &commit2)

	check := V1.Equals(commit1) && V2.Equals(commit2)
	if check {
		fmt.Println("check 1 for user", u.idx, "succeeded")
	} else {
		fmt.Println("check 1 for user", u.idx, "FAILED")
	}
}

func (u *User) checkSumProof() {
	var (
		sumProof bulletproofs.ProofBPRP
		rootV1   *p256.P256
		rootV2   *p256.P256
	)

	p, _ := bulletproofs.SetupGeneric(0, u.delta)
	root := u.path.Core[len(u.path.Core)-1]

	_ = json.Unmarshal(u.sumProof, &sumProof)
	_ = json.Unmarshal(root.C1, &rootV1)
	_ = json.Unmarshal(root.C2, &rootV2)

	//  rootV1 should equal sum(x1) - n * delta + max
	//  proofV1 should equal sum1 - n * delta + max, so same
	//  rootV2 should equal sum(x1)
	//  proofV2 should equal sum1 - gamma
	//  need dummies to compare
	dummy := int64(10)
	eta2, _ := util.CommitG1(big.NewInt(int64(dummy+u.gamma)), big.NewInt(int64(dummy)), p.BP2.H)
	zeta2, _ := util.CommitG1(big.NewInt(int64(dummy)), big.NewInt(int64(dummy)), p.BP2.H)

	adjProofV2 := new(p256.P256).Add(sumProof.P2.V, eta2)
	adjRootV2 := new(p256.P256).Add(rootV2, zeta2)

	ok1 := u.nUsers == root.L
	if !ok1 {
		fmt.Println("failure in check 2 for user", u.idx, ": #users incorrect")
	}

	ok2 := sumProof.P1.V.Equals(rootV1)
	if !ok2 {
		fmt.Println("failure in check 1 for user", u.idx, ": commitment 1 did not match sum")
	}

	ok3 := adjProofV2.Equals(adjRootV2)
	if !ok3 {
		fmt.Println("failure in check 2 for user", u.idx, ": commitment 2 did not match sum")
	}

	ok4, _ := sumProof.Verify()
	if !ok4 {
		fmt.Println("range proof failed in check 2 for user", u.idx)
	}

	if ok1 && ok2 && ok3 && ok4 {
		fmt.Println("check 2 for user", u.idx, "succeeded, can charge peak rate")
	} else {
		if ok1 && ok2 && ok3 {
			fmt.Println("check 2 for user", u.idx, "succeeded, but CANNOT charge peak rate")
		} else {
			fmt.Println("check 2 for user", u.idx, "FAILED")
		}
	}
}

func (u *User) checkRangeProofs() {
	ok0 := u.path.VerifyStructure(u.delta)
	if !ok0 {
		fmt.Println("failure in check 3 for user", u.idx, " : not a valid path")
	}
	ok123 := u.path.VerifyProofs()
	if !ok123 {
		fmt.Println("failure in check 3 for user", u.idx, " : proofs failed")
	}

	if ok0 && ok123 {
		fmt.Println("check 3 for user", u.idx, "succeeded")
	} else {
		fmt.Println("check 3 for user", u.idx, "FAILED")
	}
}

func (s *System) checkProofsSingleUser() {
	s.users[0].checkProofs()
}

func (s *System) checkProofsAllUsers() {
	for i := 0; i < s.company.nUsers; i++ {
		s.users[i].checkProofs()
	}
}

func (u *User) checkProofs() {
	u.checkCommitment()
	u.checkSumProof()
}

func initialize(n int, gamma int64, delta int64) System {
	users := make(map[int]*User)
	rs := make(map[int]*big.Int)
	for i := 0; i < n; i++ {
		r := big.NewInt(int64(rand.Int()))
		users[i] = &User{gamma, delta, n, i, 0, r, nil, nil}
		rs[i] = r
	}
	company := Company{gamma, delta, n, nil, 0, rs, nil, nil}
	return System{users, company}
}

func main() {
	if len(os.Args) < 2 {
		return
	}
	fmt.Println(os.Args[1])
	if os.Args[1] == "c" {
		startTime := time.Now().UnixNano()
		nUsers, err := strconv.Atoi(os.Args[2])
		check(err)
		system := initialize(nUsers, 400, 120)
		system.drawReadings(100)
		system.shareReadings()
		shareReadingsTime := time.Now().UnixNano()
		system.company.processReadings()
		system.shareProofData()
		processReadingsTime := time.Now().UnixNano()
		fmt.Println("sharing:", float64(shareReadingsTime-startTime)/1000000000, "seconds")
		fmt.Println("processing:", float64(processReadingsTime-shareReadingsTime)/1000000000, "seconds")

		uj := UserJSON{
			Gamma:    system.users[0].gamma,
			Delta:    system.users[0].delta,
			NUsers:   system.users[0].nUsers,
			Idx:      system.users[0].idx,
			Reading:  system.users[0].reading,
			R:        system.users[0].r,
			Path:     system.users[0].path,
			SumProof: system.users[0].sumProof,
		}
		f, _ := os.Create("user.json")
		defer f.Close()
		e := json.NewEncoder(f)
		e.Encode(uj)
	} else if os.Args[1] == "u" {
		var uj UserJSON
		f, _ := os.Open("user.json")
		defer f.Close()
		e := json.NewDecoder(f)
		e.Decode(&uj)

		user := User{
			gamma:    uj.Gamma,
			delta:    uj.Delta,
			nUsers:   uj.NUsers,
			idx:      uj.Idx,
			reading:  uj.Reading,
			r:        uj.R,
			path:     uj.Path,
			sumProof: uj.SumProof,
		}
		startTime := time.Now().UnixNano()
		user.checkProofs()
		checkReadingsTime := time.Now().UnixNano()
		fmt.Println("check time:", float64(checkReadingsTime-startTime)/1000000000, "seconds")
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
