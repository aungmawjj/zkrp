package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"time"

	"github.com/aungmawjj/zkrp/bulletproofs"
	"github.com/aungmawjj/zkrp/crypto/p256"
	"github.com/aungmawjj/zkrp/util"
)

type System struct {
	users   map[int]*User
	company Company
}

type User struct {
	d        int64
	idx      int
	reading  int
	sum      int
	r        int64
	commits1 map[int][]byte
	commits2 map[int][]byte
	proofs   map[int][]byte
	sumGamma *big.Int
}

type Company struct {
	d        int64
	nUsers   int
	readings map[int]int
	sum      int
	rs       map[int]int64
	commits1 map[int][]byte
	commits2 map[int][]byte
	proofs   map[int][]byte
	sumGamma *big.Int
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
	c.proofs = make(map[int][]byte)
	c.commits1 = make(map[int][]byte)
	c.commits2 = make(map[int][]byte)
	c.sumGamma = big.NewInt(int64(0))
	p, _ := bulletproofs.SetupGeneric(0, c.d)
	for i := 0; i < c.nUsers; i++ {
		c.sum = c.sum + c.readings[i]
		proof, _ := bulletproofs.ProveGeneric(big.NewInt(int64(c.readings[i])), p, c.rs[i])
		c.proofs[i], _ = json.Marshal(proof)
		//fmt.Println(cap(c.proofs[i]))
		c.commits1[i], _ = json.Marshal(proof.P1.V)
		c.commits2[i], _ = json.Marshal(proof.P2.V)
		rand.Seed(c.rs[i])
		c.sumGamma.Add(c.sumGamma, big.NewInt(int64(rand.Int())))
	}
}

func (c *Company) processReadingsMaliciously() {
	c.sum = 0
	c.proofs = make(map[int][]byte)
	c.commits1 = make(map[int][]byte)
	c.commits2 = make(map[int][]byte)
	c.sumGamma = big.NewInt(int64(0))
	p, _ := bulletproofs.SetupGeneric(0, c.d)
	for i := 0; i < c.nUsers; i++ {
		c.sum = c.sum + c.readings[i]
		proof1, _ := bulletproofs.ProveGeneric(big.NewInt(int64(c.readings[i])), p, c.rs[i])
		proof2, _ := bulletproofs.ProveGeneric(big.NewInt(int64(c.d-1)), p, c.rs[i])
		proof2.P1.V = proof1.P1.V
		proof2.P2.V = proof1.P2.V
		c.proofs[i], _ = json.Marshal(proof2)
		c.commits1[i], _ = json.Marshal(proof2.P1.V)
		c.commits2[i], _ = json.Marshal(proof2.P2.V)
		rand.Seed(c.rs[i])
		c.sumGamma.Add(c.sumGamma, big.NewInt(int64(rand.Int())))
	}
}

func (s *System) shareProofData() {
	for i := 0; i < s.company.nUsers; i++ {
		s.company.shareProofData(s.users[i])
	}
}

func (c *Company) shareProofData(u *User) {
	u.proofs = make(map[int][]byte)
	u.commits1 = make(map[int][]byte)
	u.commits2 = make(map[int][]byte)
	for key, value := range c.proofs {
		u.proofs[key] = value
	}
	for key, value := range c.commits1 {
		u.commits1[key] = value
	}
	for key, value := range c.commits2 {
		u.commits2[key] = value
	}
	u.sum = c.sum
	u.sumGamma = c.sumGamma
}

func (u *User) checkCommitment() {
	var (
		commit1 *p256.P256
		commit2 *p256.P256
	)
	rand.Seed(u.r)
	params, _ := bulletproofs.SetupGeneric(0, u.d)
	gamma := big.NewInt(int64(rand.Int()))
	V1, _ := util.CommitG1(big.NewInt(int64(u.reading)-u.d+bulletproofs.MAX_RANGE_END), gamma, params.BP1.H)
	V2, _ := util.CommitG1(big.NewInt(int64(u.reading)), gamma, params.BP2.H)
	_ = json.Unmarshal(u.commits1[u.idx], &commit1)
	_ = json.Unmarshal(u.commits2[u.idx], &commit2)

	check := V1.Equals(commit1) && V2.Equals(commit2)
	if check {
		fmt.Println("check 1 for user", u.idx, "succeeded")
	} else {
		fmt.Println("check 1 for user", u.idx, "FAILED")
	}
}

func (u *User) checkSum() {
	// sum after exponentiation
	params, _ := bulletproofs.SetupGeneric(0, u.d)
	var sumCommit, _ = util.CommitG1(big.NewInt(int64(u.sum)), u.sumGamma, params.BP1.H)
	var (
		commit2 *p256.P256
		Cstar   *p256.P256
	)

	// product of the commits
	_ = json.Unmarshal(u.commits2[0], &Cstar)
	for i := 1; i < len(u.commits2); i++ {
		_ = json.Unmarshal(u.commits2[i], &commit2)
		Cstar.Add(Cstar, commit2)
	}
	if Cstar.Equals(sumCommit) {
		fmt.Println("check 2 for user", u.idx, "succeeded")
	} else {
		fmt.Println("check 2 for user", u.idx, "FAILED")
	}
}

func (u *User) checkRangeProofs() {
	var (
		proof   bulletproofs.ProofBPRP
		commit1 *p256.P256
		commit2 *p256.P256
	)
	noFailures := true
	for i := 0; i < len(u.proofs); i++ {
		_ = json.Unmarshal(u.proofs[i], &proof)
		_ = json.Unmarshal(u.commits1[i], &commit1)
		_ = json.Unmarshal(u.commits2[i], &commit2)

		ok1 := proof.P1.V.Equals(commit1)
		if !ok1 {
			fmt.Println("failure in check 3 for user", u.idx, " : commitment 1 did not match")
		}
		ok2 := proof.P2.V.Equals(commit2)
		if !ok2 {
			fmt.Println("failure in check 3 for user", u.idx, " : commitment 2 did not match")
		}
		ok3, _ := proof.Verify()
		if !ok3 {
			fmt.Println("failure in check 3 for user", u.idx, " : invalid proof")
		}

		noFailures = noFailures && ok1 && ok2 && ok3
	}

	if noFailures {
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
	u.checkSum()
	u.checkRangeProofs()
}

func initialize(n int, d int64) System {
	users := make(map[int]*User)
	rs := make(map[int]int64)
	for i := 0; i < n; i++ {
		r := int64(rand.Int())
		users[i] = &User{d, i, 0, 0, r, nil, nil, nil, nil}
		rs[i] = r
	}
	company := Company{d, n, nil, 0, rs, nil, nil, nil, nil}
	return System{users, company}
}

func main() {
	start := time.Now().UnixNano()
	system := initialize(100, 128)
	system.drawReadings(100)
	system.shareReadings()
	system.company.processReadings()
	//system.company.processReadingsMaliciously()
	system.shareProofData()
	//system.checkProofsAllUsers()
	println(float64(time.Now().UnixNano()-start) / 1000000000.0)
	system.checkProofsSingleUser()
	println(float64(time.Now().UnixNano()-start) / 1000000000.0)
}
