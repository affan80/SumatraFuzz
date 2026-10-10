#include "fuzz_contract.h"
#include "sumatra_runtime.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <cstdlib>

static void check(bool ok, const char* name) {
    if (!ok) { std::cerr << "FAIL: " << name << "\n"; std::exit(1); }
}
static std::string make_pdf() {
    std::string s="%PDF-1.4\n";
    size_t offset[4]{};
    constexpr const char* objects[3]={
      "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
      "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
      "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>\nendobj\n"
    };
    for (int i=1;i<=3;++i){offset[i]=s.size();s+=objects[i-1];}
    size_t xref=s.size();
    s+="xref\n0 4\n0000000000 65535 f \n";
    for(int i=1;i<=3;++i){char buf[32];sprintf_s(buf,"%010llu 00000 n \n",static_cast<unsigned long long>(offset[i]));s+=buf;}
    return s+"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n"+std::to_string(xref)+"\n%%EOF\n";
}
static void write_bytes(const std::filesystem::path &p,const std::string &bytes){
    std::ofstream out(p,std::ios::binary|std::ios::trunc);
    check(static_cast<bool>(out),"open input for rewriting");
    out.write(bytes.data(),static_cast<std::streamsize>(bytes.size()));
    check(static_cast<bool>(out),"write input bytes");
}
int main(){
    const auto path=std::filesystem::temp_directory_path()/"SumatraFuzz A4 persistent fixture.pdf";
    auto bytes=path.u8string();
    const auto valid=make_pdf();
    // Expected to fail until the production A4 lifecycle exists.
    check(prepare_sumatra_runtime(),"prepare genuine pinned SumatraPDF runtime");
    check(prepare_sumatra_runtime(),"prepare is idempotent");
    DWORD before=0,after=0;
    check(GetProcessHandleCount(GetCurrentProcess(),&before)!=0,"read handle baseline");
    for(int i=0;i<25;++i) {
      write_bytes(path,valid);
      check(fuzz_one_file(bytes.c_str())==0,"valid PDF parsed in reentry loop");
      write_bytes(path,"%PDF-1.4\n");
      check(fuzz_one_file(bytes.c_str())==1,"truncated PDF rejected in reentry loop");
    }
    check(GetProcessHandleCount(GetCurrentProcess(),&after)!=0,"read final handle count");
    check(after<=before+8,"open-handle growth must remain bounded");
    release_sumatra_runtime();
    release_sumatra_runtime();
    std::error_code error;
    check(std::filesystem::remove(path,error)&&!error,"PDF file is unlocked after cleanup");
    std::cout<<"A4 50 genuine parser entries, rewrite and cleanup: PASS\n";
}
