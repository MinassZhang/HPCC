#ifndef COUNTMIN_H
#define COUNTMIN_H
#include <utility>
#include <algorithm>
#include <cstring>
#include <iostream>
#include "murmurhash.h"

class CountMin {

    struct CCM_type {

        //Sketch depth
        int depth;

        //Sketch width
        int  width;

        //Counter table
        unsigned long * counts;
        unsigned long * hash;

        //# key bits
        int lgn;
    };

public:
    CountMin(int depth,int width);

    ~CountMin();

    void Update(uint64_t item, int weight);

    unsigned long Query(uint64_t item);

private:

    //Sketch data structure
    CCM_type ccm_;

};

CountMin::CountMin(int depth,int width) {
    ccm_.depth = depth;
    ccm_.width = width;
    ccm_.lgn = 64;
    ccm_.counts = new unsigned long[ccm_.depth*ccm_.width]();
    ccm_.hash = new unsigned long[ccm_.depth];
    char name[] = "CountMin";
    unsigned long seed = AwareHash((unsigned char*)name, strlen(name), 13091204281, 228204732751, 6620830889);
    for (int i = 0; i < ccm_.depth; i++) {
        ccm_.hash[i] = GenHashSeed(seed++);
    }
}

CountMin::~CountMin() {
    delete [] ccm_.hash;
    delete [] ccm_.counts;
}

void CountMin::Update(uint64_t item, int val) {
    for (int i = 0; i < ccm_.depth; i++) {
        unsigned long bucket = MurmurHash64A((unsigned char *)&item, ccm_.lgn/8, ccm_.hash[i]) % ccm_.width;
        int index =  i*ccm_.width+bucket;
        ccm_.counts[index] += val;
    }
}



unsigned long CountMin::Query(uint64_t item) {
    uint64_t result(UINT64_MAX);
    for (int i = 0; i < ccm_.depth; i++) {
        unsigned long bucket = MurmurHash64A((unsigned char *)&item, ccm_.lgn/8, ccm_.hash[i]) % ccm_.width;
        int index =  i*ccm_.width+bucket;
        result = std::min(result, ccm_.counts[index]);
    }
    return result;
}

#endif