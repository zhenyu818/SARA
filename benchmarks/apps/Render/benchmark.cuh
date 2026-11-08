// Adapted from Manan1406/RayTracer-CUDA, MIT; origin and license are listed in THIRD_PARTY.md.
#include "../common/benchmark_support.cuh"
namespace sb = sara_bench;
struct RenderVec { float x, y, z; };
struct RenderSphere { RenderVec center; float radius; RenderVec color; };
__device__ RenderVec rv_add(RenderVec a, RenderVec b) { return RenderVec{a.x+b.x, a.y+b.y, a.z+b.z}; }
__device__ RenderVec rv_sub(RenderVec a, RenderVec b) { return RenderVec{a.x-b.x, a.y-b.y, a.z-b.z}; }
__device__ RenderVec rv_scale(RenderVec a, float s) { return RenderVec{a.x*s, a.y*s, a.z*s}; }
__device__ float rv_dot(RenderVec a, RenderVec b) { return a.x*b.x+a.y*b.y+a.z*b.z; }
__device__ RenderVec rv_normalize(RenderVec a) { return rv_scale(a, 1.0f/sqrtf(rv_dot(a,a))); }
__device__ float render_hit(RenderSphere sphere, RenderVec direction) {
    RenderVec oc = rv_scale(sphere.center, -1.0f);
    float a = rv_dot(direction, direction), b = 2.0f*rv_dot(direction, oc);
    float c = rv_dot(oc,oc)-sphere.radius*sphere.radius, disc = b*b-4.0f*a*c;
    if (disc < 0.0f) return -1.0f;
    float root = sqrtf(disc), near_t = (-b-root)/(2.0f*a), far_t = (-b+root)/(2.0f*a);
    if (near_t > 0.0f) return near_t;
    return far_t > 0.0f ? far_t : -1.0f;
}
__device__ RenderVec render_color(RenderVec direction, RenderSphere a, RenderSphere b, RenderVec light) {
    float ta = render_hit(a, direction), tb = render_hit(b, direction), t = ta;
    RenderSphere hit = a;
    if (tb > 0.0f && (ta <= 0.0f || tb < ta)) { t = tb; hit = b; }
    if (t > 0.0f) {
        RenderVec point = rv_scale(direction,t), normal = rv_normalize(rv_sub(point,hit.center));
        RenderVec towards_light = rv_normalize(rv_sub(light,point));
        float brightness = 0.1f+0.9f*fmaxf(rv_dot(towards_light,normal),0.0f);
        return rv_scale(hit.color,brightness);
    }
    float y = 0.5f*(direction.y+1.0f);
    return RenderVec{(1.0f-y)+y*(100.0f/255.0f), (1.0f-y)+y*(150.0f/255.0f), 1.0f};
}
__global__ void render_kernel(unsigned char *image, const float *jitter, int width, int height, int samples,
                               RenderSphere a, RenderSphere b, RenderVec light) {
    int pixel = blockIdx.x*blockDim.x+threadIdx.x;
    if (pixel >= width*height) return;
    int x = pixel%width, y = pixel/width;
    RenderVec sum = {0.0f,0.0f,0.0f};
    for (int sample=0; sample<samples; ++sample) {
        int index = (pixel*samples+sample)*2;
        float u = (x+jitter[index])/width, v = (y+jitter[index+1])/height;
        RenderVec direction = {(2.0f*u-1.0f)*(static_cast<float>(width)/height), 1.0f-2.0f*v, -1.0f};
        sum = rv_add(sum,render_color(rv_normalize(direction),a,b,light));
    }
    float channel[3] = {sum.x/samples,sum.y/samples,sum.z/samples};
    for (int c=0;c<3;++c) image[pixel*3+c] = static_cast<unsigned char>(255.0f*fminf(fmaxf(channel[c],0.0f),1.0f));
}
int main(int argc,char **argv) {
    {
    if (argc!=4) sb::fail("usage: Render width height samples_per_pixel");
    int width=sb::integer(argv[1]),height=sb::integer(argv[2]),samples=sb::integer(argv[3]);
    int pixels=sb::product(width,height), output_count=sb::product(pixels,3);
    int jitter_count=sb::product(sb::product(pixels,samples),2);
    std::vector<float> jitter(jitter_count); sb::Rng rng;
    for(float &v:jitter) v=rng.uniform();
    RenderSphere a={{0.0f,0.0f,-1.0f},0.5f,{1.0f,0.0f,0.0f}};
    RenderSphere b={{0.8f,-0.1f,-1.5f},0.35f,{0.0f,1.0f,0.0f}};
    RenderVec light={-2.0f,2.0f,0.0f};
    sb::DeviceBuffer<float> dj(jitter.size()); sb::DeviceBuffer<unsigned char> image(output_count);
    dj.upload(jitter);
    render_kernel<<<sb::ceil_div(pixels,256),256>>>(image.get(),dj.get(),width,height,samples,a,b,light);
    sb::finish_kernel();
    std::vector<unsigned char> out=sb::output("rgb","u8",image.get(),output_count);
    if(sb::validate_cpu()) {
        // Independent double-precision scalar ray caster; integer image tolerance is one LSB.
        for(int pixel=0;pixel<pixels;++pixel) {
            double sum[3]={0,0,0};
            for(int sample=0;sample<samples;++sample) {
                int j=(pixel*samples+sample)*2;
                double u=((pixel%width)+static_cast<double>(jitter[j]))/width;
                double v=((pixel/width)+static_cast<double>(jitter[j+1]))/height;
                double dir[3]={(2*u-1)*static_cast<double>(width)/height,1-2*v,-1};
                double norm=std::sqrt(dir[0]*dir[0]+dir[1]*dir[1]+dir[2]*dir[2]);
                for(int c=0;c<3;++c) dir[c]/=norm;
                RenderSphere spheres[2]={a,b}; int hit=-1; double best=std::numeric_limits<double>::infinity();
                for(int s=0;s<2;++s) {
                    double cx=spheres[s].center.x,cy=spheres[s].center.y,cz=spheres[s].center.z;
                    double half_b=-(dir[0]*cx+dir[1]*cy+dir[2]*cz);
                    double cc=cx*cx+cy*cy+cz*cz-static_cast<double>(spheres[s].radius)*spheres[s].radius;
                    double disc=half_b*half_b-cc;
                    if(disc<0) continue;
                    double near_t=-half_b-std::sqrt(disc),far_t=-half_b+std::sqrt(disc);
                    double t=near_t>0?near_t:far_t;
                    if(t>0&&t<best) {best=t;hit=s;}
                }
                if(hit>=0) {
                    double center[3]={spheres[hit].center.x,spheres[hit].center.y,spheres[hit].center.z};
                    double lp[3]={light.x,light.y,light.z},normal[3],to_light[3],nn=0,ln=0;
                    for(int c=0;c<3;++c) {normal[c]=dir[c]*best-center[c];to_light[c]=lp[c]-dir[c]*best;nn+=normal[c]*normal[c];ln+=to_light[c]*to_light[c];}
                    double dot=0;for(int c=0;c<3;++c) dot+=(normal[c]/std::sqrt(nn))*(to_light[c]/std::sqrt(ln));
                    double brightness=static_cast<double>(0.1f)+static_cast<double>(0.9f)*std::max(dot,0.0);
                    sum[0]+=brightness*spheres[hit].color.x;sum[1]+=brightness*spheres[hit].color.y;sum[2]+=brightness*spheres[hit].color.z;
                } else {
                    double t=0.5*(dir[1]+1);sum[0]+=(1-t)+t*static_cast<double>(100.0f/255.0f);
                    sum[1]+=(1-t)+t*static_cast<double>(150.0f/255.0f);sum[2]+=1;
                }
            }
            for(int c=0;c<3;++c) {
                int expected=static_cast<int>(255.0*std::min(1.0,std::max(0.0,sum[c]/samples)));
                if(std::abs(static_cast<int>(out[pixel*3+c])-expected)>1) sb::fail("Render CPU image differs by more than one LSB");
            }
        }

    }
    } // All DeviceBuffer destructors have completed their cudaFree calls.
    SARA_CUDA(cudaDeviceSynchronize());
    SARA_CUDA(cudaThreadExit());
    if (sb::validate_cpu()) sb::validation_passed("Render");
    return 0;
}
