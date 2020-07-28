#ifndef __SOUND_CORE_H__
#define __SOUND_CORE_H__

int register_sound_special(struct file_operations *fops, int unit);
int register_sound_mixer(struct file_operations *fops, int dev);
int register_sound_midi(struct file_operations *fops, int dev);
int register_sound_dsp(struct file_operations *fops, int dev);
int register_sound_synth(struct file_operations *fops, int dev);

void unregister_sound_special(int unit);
void unregister_sound_mixer(int unit);
void unregister_sound_midi(int unit);
void unregister_sound_dsp(int unit);
void unregister_sound_synth(int unit);

#endif
