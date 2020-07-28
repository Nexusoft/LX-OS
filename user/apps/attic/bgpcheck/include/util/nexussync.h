#ifndef NEXUS_SYNC_H_SHIELD
#define NEXUS_SYNC_H_SHIELD

class Semaphore {
  public:
    Semaphore(int count);
    ~Semaphore();
    void up();
    void down();
    
  private:
    void *sema;
};

#endif
