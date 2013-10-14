// This file is part of FTE.
//
// FTE is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// FTE is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with FTE.  If not, see <http://www.gnu.org/licenses/>.

#include <stdio.h>
#include <string>
#include <fstream>
#include <streambuf>

#include "util/test.h"
#include "util/thread.h"
#include "re2/prog.h"
#include "re2/re2.h"
#include "re2/regexp.h"
#include "re2/testing/regexp_generator.h"
#include "re2/testing/string_generator.h"

#include <boost/algorithm/string.hpp>

using namespace re2;

class BuildThread : public Thread {
 public:
  BuildThread(Prog* prog) : prog_(prog) {}
  virtual void Run() {
    CHECK(prog_->BuildEntireDFA(Prog::kFirstMatch));
  }

 private:
  Prog* prog_;
};

int main(int argc, char *argv[])
{
    if (argc>=2) {
        std::ifstream t(argv[argc-1]);
        std::string s;

        t.seekg(0, std::ios::end);
        s.reserve(t.tellg());
        t.seekg(0, std::ios::beg);

        s.assign((std::istreambuf_iterator<char>(t)),
                    std::istreambuf_iterator<char>());

        RE2::Options opt;
        opt.set_max_mem((int64_t)1<<40);

        Regexp* re = Regexp::Parse(s.c_str(), Regexp::ClassNL | Regexp::OneLine | Regexp::PerlClasses | Regexp::PerlB | Regexp::PerlX | Regexp::Latin1, NULL);
        Prog* prog = re->CompileToProg(opt.max_mem());
        prog->BuildEntireDFA(Prog::kFullMatch);
        
        delete prog;
        re->Decref();
    }

    return 0;
}
