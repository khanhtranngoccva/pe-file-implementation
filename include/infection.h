#pragma once

#include <argparse/argparse.hpp>
#include <cstdlib>
#include <iostream>
#include "pe.h"
#include "exception.h"

void infectPE(PE &input, PE &payload86, PE &payload64, std::string &payload86SectionName,
              std::string &payload64SectionName);