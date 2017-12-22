# coding='utf8'

import docker
from docker import APIClient
import docker.errors

# Ref for Docker-py http://docker-py.readthedocs.io/en/stable/containers.html
def create_container(client, instance):
	param_list = {}
	VOL_RIGHTS = 'rw'  # TODO this option will open to customer in advance option in crate instance
	environment = instance.env_params.split(',')
	environment = [ e for e in environment if e != '']
	volumns = {}
	runtime = ''
	for p in instance.share_folder.split(','):
		volumns[p.split(':')[0]] = {'bind': p.split(':')[1], 'mode': VOL_RIGHTS}
	if instance.with_gpu and instance.gpu_ids != 0:
		runtime = 'nvidia'
		environment.append("NVIDIA_VISIBLE_DEVICES=" + instance.gpu_ids)

	if len(environment) > 0:
		param_list['environment'] = environment
	if runtime != '':
		param_list['runtime'] = runtime
	if len(volumns) > 0:
		param_list['volumes'] = volumns
	# TODO add the port mapping list
	param_list['detach'] = True
	param_list['name'] = instance.instance_name

	container_id = client.create_container(image=instance.image_id, **param_list)
	return container_id

def start_container(client, container_id):
	## Parameter option are not support
	try:
		response = client.start(container=container_id)
		return response
	except docker.errors.APIError as ae:
		return ae.message


def remove_container(client, container_id):
	try:
		client.remove(container=container_id)
		# TODO need add the [v], [link] and [force] options in instance management page
		return '0'
	except docker.errors.APIError as ae:
		return ae.message

def stop_container(client, container_id):
	try:
		client.stop(container=container_id)
		return '0'
	except docker.errors.APIError as ae:
		return ae.message

def get_port_of_container(clinet, container_id):
	pass

if __name__ == "__main__":
	# client = docker.from_env()
	cli = APIClient(base_url='unix:///var/run/docker.sock')
	r = cli.port('edd35e794274')
